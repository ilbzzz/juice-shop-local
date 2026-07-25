/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const configObject = config.util.toObject(config)
    const safeConfig = {
      application: structuredClone(configObject.application)
    }
    if (safeConfig.application?.chatBot) {
      delete (safeConfig.application.chatBot as any).llmApiUrl
    }
    if (safeConfig.application?.googleOauth) {
      delete (safeConfig.application as any).googleOauth
    }
    res.json({ config: safeConfig })
  }
}
