/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import net from 'node:net'
import dns from 'node:dns'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrInternalIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return true
    }
    const [a, b, c] = parts
    if (a === 0) return true // 0.0.0.0/8
    if (a === 10) return true // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true // 100.64.0.0/10
    if (a === 127) return true // 127.0.0.0/8
    if (a === 169 && b === 254) return true // 169.254.0.0/16
    if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12
    if (a === 192 && b === 0 && c === 0) return true // 192.0.0.0/24
    if (a === 192 && b === 0 && c === 2) return true // 192.0.2.0/24
    if (a === 192 && b === 88 && c === 99) return true // 192.88.99.0/24
    if (a === 192 && b === 168) return true // 192.168.0.0/16
    if (a === 198 && (b === 18 || b === 19)) return true // 198.18.0.0/15
    if (a === 198 && b === 51 && c === 100) return true // 198.51.100.0/24
    if (a === 203 && b === 0 && c === 113) return true // 203.0.113.0/24
    if (a >= 224) return true // 224.0.0.0/4 Multicast & 240.0.0.0/4 Reserved & Broadcast

    return false
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase()
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1' || normalized === '::0001') return true
    if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true
    if (normalized.startsWith('::ffff:')) {
      const v4Part = normalized.substring(7)
      if (net.isIPv4(v4Part)) {
        return isPrivateOrInternalIp(v4Part)
      }
      const hexParts = v4Part.split(':')
      if (hexParts.length === 2) {
        const p1 = parseInt(hexParts[0], 16)
        const p2 = parseInt(hexParts[1], 16)
        if (!isNaN(p1) && !isNaN(p2)) {
          const b1 = (p1 >> 8) & 0xff
          const b2 = p1 & 0xff
          const b3 = (p2 >> 8) & 0xff
          const b4 = p2 & 0xff
          return isPrivateOrInternalIp(`${b1}.${b2}.${b3}.${b4}`)
        }
      }
    }
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true
    if (/^fe[89ab]/i.test(normalized)) return true
    if (normalized.startsWith('ff')) return true

    return false
  }

  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return false
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  let hostname = parsedUrl.hostname.toLowerCase()
  if (!hostname) {
    return false
  }

  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1)
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.arpa') ||
    hostname.endsWith('.lan') ||
    hostname === 'ip6-localhost' ||
    hostname === 'ip6-loopback'
  ) {
    return false
  }

  if (net.isIP(hostname)) {
    return !isPrivateOrInternalIp(hostname)
  }

  try {
    const addresses = await dns.promises.lookup(hostname, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    for (const record of addresses) {
      if (isPrivateOrInternalIp(record.address)) {
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
          res.status(400)
          next(new Error('Invalid or disallowed image URL'))
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
