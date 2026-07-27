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
      server: {
        port: configObject.server?.port
      },
      application: {
        domain: configObject.application?.domain,
        name: configObject.application?.name,
        logo: configObject.application?.logo,
        favicon: configObject.application?.favicon,
        theme: configObject.application?.theme,
        showVersionNumber: configObject.application?.showVersionNumber,
        showGitHubLinks: configObject.application?.showGitHubLinks,
        localBackupEnabled: configObject.application?.localBackupEnabled,
        numberOfRandomFakeUsers: configObject.application?.numberOfRandomFakeUsers,
        altcoinName: configObject.application?.altcoinName,
        privacyContactEmail: configObject.application?.privacyContactEmail,
        social: configObject.application?.social,
        chatBot: {
          name: configObject.application?.chatBot?.name,
          avatar: configObject.application?.chatBot?.avatar,
          sampleQuestions: configObject.application?.chatBot?.sampleQuestions
        },
        recyclePage: configObject.application?.recyclePage,
        welcomeBanner: configObject.application?.welcomeBanner,
        cookieConsent: configObject.application?.cookieConsent,
        securityTxt: configObject.application?.securityTxt,
        promotion: configObject.application?.promotion,
        easterEggPlanet: configObject.application?.easterEggPlanet
      },
      hackingInstructor: {
        isEnabled: configObject.hackingInstructor?.isEnabled,
        avatarImage: configObject.hackingInstructor?.avatarImage
      },
      ctf: {
        showFlagsInNotifications: configObject.ctf?.showFlagsInNotifications,
        showCountryDetailsInNotifications: configObject.ctf?.showCountryDetailsInNotifications,
        countryMapping: configObject.ctf?.countryMapping,
        systemWideNotifications: configObject.ctf?.systemWideNotifications
      }
    }
    res.json({ config: safeConfig })
  }
}
