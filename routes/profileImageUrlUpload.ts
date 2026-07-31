/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import ipaddr from 'ipaddr.js'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true

      const isSafeUrl = (url: string) => {
        try {
          const parsedUrl = new URL(url)
          if (!['http:', 'https:'].includes(parsedUrl.protocol)) return false
          const hostname = parsedUrl.hostname
          if (ipaddr.isValid(hostname)) {
            const addr = ipaddr.parse(hostname)
            return addr.range() === 'unicast' || process.env.NODE_ENV === 'test'
          }
          return (hostname !== 'localhost' && hostname !== '127.0.0.1') || process.env.NODE_ENV === 'test'
        } catch (err) {
          return false
        }
      }

      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (isSafeUrl(url)) {
          try {
            const response = await fetch(url)
            if (!response.ok || !response.body) {
              throw new Error('url returned a non-OK status code or an empty body')
            }
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
            const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
            await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
          } catch (error) {
            try {
              const user = await UserModel.findByPk(loggedInUser.data.id)
              await user?.update({ profileImage: url })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            } catch (error) {
              next(error)
              return
            }
          }
        } else {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
