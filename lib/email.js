require('dotenv').config()
var SibApiV3Sdk = require('sib-api-v3-sdk')
var defaultClient = SibApiV3Sdk.ApiClient.instance
var sib_apiKey = process.env.SENDINBLUE_API_KEY

const SendSmtpEmail = SibApiV3Sdk.SendSmtpEmail
exports.SendSmtpEmail = SendSmtpEmail

const linkFactory = {
  Rdv: function({domain}, {data}) {
    return `https://${domain}/organisations/${data.organisation.id}/rdvs/${data.id}`
  },
  PlageOuverture: function({domain}, {data}) {
    return `https://${domain}/organisations/${data.organisation.id}/agents/${data.agent.id}/plage_ouvertures`
  }
}
exports.linkFactory = linkFactory

function sendEmail(sendSmtpEmail) {
  var apiKey = defaultClient.authentications['api-key']
  apiKey.apiKey = sib_apiKey
  var partnerKey = defaultClient.authentications['partner-key']
  partnerKey.apiKey = sib_apiKey

  var apiInstance = new SibApiV3Sdk.SMTPApi()

  sendSmtpEmail.sender = {
    name: 'Équipe RDV-Solidarités',
    email: 'contact@rdv-solidarites.fr'
  }
  return apiInstance.sendTransacEmail(sendSmtpEmail)
}
exports.sendEmail = sendEmail
