/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv6 (ip: string): boolean {
  const cleanIp = ip.toLowerCase().trim()
  if (cleanIp === '::' || cleanIp === '::1') return true
  if (cleanIp === '0:0:0:0:0:0:0:0' || cleanIp === '0:0:0:0:0:0:0:1') return true

  if (cleanIp.includes('ffff:')) {
    const afterFfff = cleanIp.split('ffff:')[1]
    if (afterFfff) {
      if (afterFfff.includes('.')) {
        return isPrivateOrReservedIp(afterFfff)
      }
      const hexParts = afterFfff.split(':')
      if (hexParts.length === 2) {
        const p1 = parseInt(hexParts[0], 16)
        const p2 = parseInt(hexParts[1], 16)
        if (!isNaN(p1) && !isNaN(p2)) {
          const ipv4 = `${(p1 >> 8) & 255}.${p1 & 255}.${(p2 >> 8) & 255}.${p2 & 255}`
          return isPrivateOrReservedIp(ipv4)
        }
      }
    }
    return true
  }

  const blocks = cleanIp.split(':').filter(Boolean)
  if (blocks.length > 0) {
    const first = parseInt(blocks[0], 16)
    if (!isNaN(first)) {
      if (first >= 0xfc00 && first <= 0xfdff) return true
      if (first >= 0xfe80 && first <= 0xfebf) return true
      if (first >= 0xff00 && first <= 0xffff) return true
      if (first === 0x100) return true
      if (first === 0x2001 && blocks.length > 1) {
        const second = parseInt(blocks[1], 16)
        if (second === 0xdb8) return true
      }
    }
  }

  return false
}

function isPrivateOrReservedIp (ip: string): boolean {
  const version = net.isIP(ip)
  if (version === 4) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) {
      return true
    }
    const [a, b, c] = parts
    if (a === 0) return true
    if (a === 10) return true
    if (a === 100 && b >= 64 && b <= 127) return true
    if (a === 127) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 0 && c === 0) return true
    if (a === 192 && b === 0 && c === 2) return true
    if (a === 192 && b === 88 && c === 99) return true
    if (a === 192 && b === 168) return true
    if (a === 198 && (b === 18 || b === 19)) return true
    if (a === 198 && b === 51 && c === 100) return true
    if (a === 203 && b === 0 && c === 113) return true
    if (a >= 224) return true
    return false
  } else if (version === 6) {
    return isPrivateIPv6(ip)
  }
  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  if (typeof urlString !== 'string' || !urlString.trim()) {
    return false
  }
  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return false
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (!hostname) {
    return false
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.localdomain') ||
    hostname.endsWith('.home.arpa')
  ) {
    return false
  }

  if (net.isIP(hostname)) {
    return !isPrivateOrReservedIp(hostname)
  }

  try {
    const addresses = await dns.lookup(hostname, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    for (const record of addresses) {
      if (isPrivateOrReservedIp(record.address)) {
        return false
      }
    }
  } catch {
    return false
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url === 'string' && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url !== 'string' || !(await isSafeUrl(url))) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          let currentUrl = url
          let response: globalThis.Response | undefined
          for (let i = 0; i < 5; i++) {
            if (!(await isSafeUrl(currentUrl))) {
              throw new Error('Unsafe redirect URL')
            }
            const res = await fetch(currentUrl, { redirect: 'manual' })
            if ([301, 302, 303, 307, 308].includes(res.status)) {
              const location = res.headers.get('location')
              if (!location) {
                throw new Error('Redirect without location header')
              }
              currentUrl = new URL(location, currentUrl).toString()
              continue
            }
            response = res
            break
          }
          if (!response || !response.ok || !response.body) {
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
