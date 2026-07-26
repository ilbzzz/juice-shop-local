/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const configObject = config.util.toObject(config)
    const safeConfig: any = {}
    const allowedKeys = ['application', 'challenges', 'hackingInstructor', 'ctf']
    for (const key of allowedKeys) {
      if (configObject[key] !== undefined) {
        safeConfig[key] = structuredClone(configObject[key])
      }
    }

    if (safeConfig.application?.chatBot) {
      delete safeConfig.application.chatBot.llmApiUrl
    }
    if (safeConfig.application?.googleOauth) {
      delete safeConfig.application.googleOauth
    }
    res.json({ config: safeConfig })
  }
}
