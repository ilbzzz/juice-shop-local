/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function responseText (res: request.Response): string {
  return res.text ?? (Buffer.isBuffer(res.body) ? res.body.toString('utf-8') : '')
}

void describe('/ftp', () => {
  void it('GET serves a directory listing', async () => {
    const res = await request(app)
      .get('/ftp')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<title>listing directory /ftp</title>'))
  })

  void it('GET a non-existing Markdown file in /ftp will return a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/doesnotexist.md')
    assert.equal(res.status, 404)
  })

  void it('GET a non-existing PDF file in /ftp will return a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/doesnotexist.pdf')
    assert.equal(res.status, 404)
  })

  void it('GET a non-existing file in /ftp will return a 403 error for invalid file type', async () => {
    const res = await request(app)
      .get('/ftp/doesnotexist.exe')
    assert.equal(res.status, 403)
  })

  void it('GET an existing file in /ftp will return a 403 error for invalid file type .gg', async () => {
    const res = await request(app)
      .get('/ftp/eastere.gg')
    assert.equal(res.status, 403)
  })

  void it('GET existing file /ftp/coupons_2013.md.bak will return a 403 error for invalid file type .bak', async () => {
    const res = await request(app)
      .get('/ftp/coupons_2013.md.bak')
    assert.equal(res.status, 403)
  })

  void it('GET existing file /ftp/package.json.bak will return a 403 error for invalid file type .bak', async () => {
    const res = await request(app)
      .get('/ftp/package.json.bak')
    assert.equal(res.status, 403)
  })

  void it('GET existing file /ftp/suspicious_errors.yml will return a 403 error for invalid file type .yml', async () => {
    const res = await request(app)
      .get('/ftp/suspicious_errors.yml')
    assert.equal(res.status, 403)
  })

  void it('GET the confidential file in /ftp', async () => {
    const res = await request(app)
      .get('/ftp/acquisitions.md')
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('# Planned Acquisitions'))
  })

  void it('GET the KeePass database in /ftp', async () => {
    const res = await request(app)
      .get('/ftp/incident-support.kdbx')
    assert.equal(res.status, 200)
  })

