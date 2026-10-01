/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ipStr: string): boolean {
  let ip = ipStr.replace(/^\[|\]$/g, '').toLowerCase()
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7)
  }

  const family = net.isIP(ip)
  if (family === 4) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) return true

    const [a, b, c] = parts
    if (a === 0 || a === 10 || a === 127) return true
    if (a === 100 && b >= 64 && b <= 127) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 192 && b === 0 && c === 0) return true
    if (a === 192 && b === 0 && c === 2) return true
    if (a === 198 && b === 51 && c === 100) return true
    if (a === 203 && b === 0 && c === 113) return true
    if (a >= 224) return true

    return false
  }

  if (family === 6) {
    if (ip === '::1' || ip === '::' || ip === '0:0:0:0:0:0:0:1' || ip === '0:0:0:0:0:0:0:0') return true
    if (ip.startsWith('fe8') || ip.startsWith('fe9') || ip.startsWith('fea') || ip.startsWith('feb')) return true
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true
    return false
  }

  return true
}

function isDisallowedHost (hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase()

  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.lan') || host.endsWith('.home') || host.endsWith('.arpa') || host === 'instance-data') {
    return true
  }

  if (net.isIP(host) !== 0 || host.startsWith('::ffff:')) {
    return isPrivateIp(host)
  }

  return false
}

async function isUnsafeUrl (urlStr: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(urlStr)
  } catch {
    return true
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return true
  }

  const hostname = parsed.hostname
  if (isDisallowedHost(hostname)) {
    return true
  }

  const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (net.isIP(cleanHost) === 0) {
    try {
      const addresses = await dns.lookup(cleanHost, { all: true })
      for (const addr of addresses) {
        if (isPrivateIp(addr.address)) {
          return true
        }
      }
    } catch {
      // DNS lookup failed; allow fetch to attempt request and fail safely
    }
  }

  return false
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (await isUnsafeUrl(url)) {
          next(new Error('Unrecognized target URL'))
          return
        }
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
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
