var { SendSmtpEmail, sendEmail, linkFactory } = require('../email')
var { build } = require('./process')

async function core(req) {
  var endpoint = req.endpoint.data
  var input = req.input

  if (!endpoint.domain) {
    throw "Cannot send: missing 'domain'."
  }

  if (!endpoint.email) {
    throw "Cannot send: missing 'email'."
  }

  if (input.meta.model !== "Rdv") {
    throw `Ignoring model ${input.meta.model}.`
  } else {
    req.steps.push(`Processing Rdv.`)
  }

  if (input.meta.event !== "created") {
    throw `Ignoring '${input.meta.event}' event.`
  } else {
    req.steps.push(`Processing '${input.meta.event}' event.`)
  }

  await build(req)
}

async function process(req) {
  try {
    await core(req)
    var endpoint = req.endpoint.data
    var input = req.input

    if (req.response.id) {
      req.steps.push(`Success: ${req.response.id}`)
    } else {
      req.steps.push(`Failure: ${req.response.error}`)
    }
  } catch(e) {
    req.steps.push(e)
    req.response = {
      err: e
    }
  }
}

async function processRequest(req, res, next) {
  try {
    await process(req)
    var endpoint = req.endpoint.data
    var input = req.input


    var email = new SendSmtpEmail()
    email.to = [{email: endpoint.email}]
    email.subject = `${req.steps[req.steps.length -1]} (id: ${input.data.id})`

    email.htmlContent = `
    <p><a href="${linkFactory[input.meta.model](endpoint, input)}">lien</a></p>
    <ul>${req.steps.map(s => `<li>${s}</li>`).join('\n')}</ul>
    `
    sendEmail(email).then((msg) => {
      req.steps.push(`send: ✅ ${msg.messageId}`)
      next()
    }).catch(err => {
      req.steps.push(`error: ${err}`)
      next(err)
    })
  } catch(e) {
    console.log(e)
    req.steps.push(e)
    req.response = {
      err: e
    }
    next(e)
  }
}

module.exports = {
  processRequest,
}
