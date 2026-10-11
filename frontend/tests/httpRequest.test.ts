import assert from 'node:assert/strict'
import test from 'node:test'
import { buildImportFormData } from '../src/lib/datasetImport.ts'
import { buildRequestInit } from '../src/services/httpRequest.ts'

const API = 'http://127.0.0.1:8000/api/imports'

test('JSON bodies keep the JSON content type and are serialised', () => {
  const init = buildRequestInit('POST', 'token-1', { assetId: 'a1' })
  assert.deepEqual(init.headers, { 'Content-Type': 'application/json', Authorization: 'Bearer token-1' })
  assert.equal(init.body, '{"assetId":"a1"}')
  assert.equal(init.method, 'POST')
})

test('requests without a body send none and omit Authorization when signed out', () => {
  const init = buildRequestInit('GET', null)
  assert.equal(init.body, undefined)
  assert.deepEqual(init.headers, { 'Content-Type': 'application/json' })
})

test('FormData uploads are sent as-is with no forced Content-Type', () => {
  const form = buildImportFormData(new Blob(['a,b\n1,2\n']), 'flows.csv', 'generic-csv')
  const init = buildRequestInit('POST', 'token-1', form)
  assert.equal(init.body, form)
  assert.deepEqual(init.headers, { Authorization: 'Bearer token-1' })
})

test('the runtime supplies a multipart boundary and the exact backend field names', async () => {
  const form = buildImportFormData(new Blob(['a,b\n1,2\n'], { type: 'text/csv' }), 'flows.csv', 'generic-csv')
  const request = new Request(API, buildRequestInit('POST', 'token-1', form))

  assert.match(request.headers.get('content-type') ?? '', /^multipart\/form-data; boundary=.+/)
  assert.equal(request.headers.get('authorization'), 'Bearer token-1')
  const parsed = await request.formData()
  assert.deepEqual([...parsed.keys()].sort(), ['file', 'profile'])
  assert.equal(parsed.get('profile'), 'generic-csv')
  const file = parsed.get('file')
  assert.ok(file instanceof File)
  assert.equal(file.name, 'flows.csv')
  assert.equal(await file.text(), 'a,b\n1,2\n')
})
