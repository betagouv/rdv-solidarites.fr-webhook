var { SendSmtpEmail, sendEmail } = require('../email')

const linkFactory = {
  Rdv: function({domain}, {data}) {
    return `https://${domain}/organisations/${data.organisation.id}/rdvs/${data.id}`
  },
  PlageOuverture: function({domain}, {data}) {
    return `https://${domain}/organisations/${data.organisation.id}/agents/${data.agent.id}/plage_ouvertures`
  }
}

exports.processRequest = function(req, res, next) {
  var endpoint = req.endpoint.data
  var input = req.input

  if (!endpoint.domain) {
    req.steps.push("Cannot send: missing 'domain'.")
    return next()
  }

  if (!endpoint.email) {
    req.steps.push("Cannot send: missing 'email'.")
    return next()
  }

  var email = new SendSmtpEmail()
  email.to = [{email: endpoint.email}]
  email.subject = `${input.meta.model} ${input.meta.event} (id: ${input.data.id})`
  email.htmlContent = `
  <p><a href="${linkFactory[input.meta.model](endpoint, input)}">lien</a></p>
  <pre>${JSON.stringify(input, null, 2)}</pre>
  `
  sendEmail(email).then((msg) => {
    req.steps.push(`send: ✅ ${msg.messageId}`)
    next()
  }).catch(err => {
    req.steps.push(`error: ${err}`)
    next(err)
  })
}