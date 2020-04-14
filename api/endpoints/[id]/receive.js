const { q, client } = require('../../../lib/db')
const { addBody, addEndpoint, addSteps, runMiddleware } = require('../../../lib/internal')
const { checkSignaturePresence, checkSignatureValidity } = require('../../../lib/sign')

const { processRequest } = require('../../../lib/hauts_de_seine')

export const config = {
  api: {
    bodyParser: false
  },
}

async function savePayload(req, res, next) {
  const dbs = await client.query(
    q.Create(
      q.Collection("payloads"),
      {
        data: {
          body: req.input,
          endpoint: req.endpoint.ref.id,
          public: !req.endpoint.data.secret || Boolean(req.endpoint.data.public)
        }
      }
    )
  )

  req.payload_id = dbs.ref.id
  req.payload = dbs.data
  next()
}

async function saveProcess(req, res, next) {
  const dbs = await client.query(
    q.Create(
      q.Collection("processes"),
      {
        data: {
          payload: req.payload_id,
          steps: req.steps,
          response: req.response
        }
      }
    )
  )

  req.payload = dbs.data
  next()
}

export default async (req, res) => {
  try {
    await runMiddleware(req, res, addEndpoint)
    await runMiddleware(req, res, addBody)
    await runMiddleware(req, res, addSteps)

    try {
      req.input = JSON.parse(req.body)
      await runMiddleware(req, res, savePayload)
      await runMiddleware(req, res, checkSignaturePresence)
      await runMiddleware(req, res, checkSignatureValidity)

      //
      //await runMiddleware(req, res, processRequest)
      //
    } catch (e) {
      req.steps.push(`error ❌`)
      req.response = { error: e.toString() }
    }

    await runMiddleware(req, res, saveProcess)

    res.status(200).json({
      payload: req.payload,
      steps: req.steps,
      response: req.response || { status: 'ok' }
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
}
