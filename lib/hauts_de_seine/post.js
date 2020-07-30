require('dotenv').config()
const rp = require('request-promise')
const path = require('path')
const fs = require('fs')
const Handlebars = require('handlebars')
const parseString = require('xml2js').parseString

const templatePath = path.join(__dirname, 'templates', 'bookRequestXSlim.xml.hbs')
const bookRequestTemplate = Handlebars.compile(fs.readFileSync(templatePath, 'utf-8'))


function processResponse(payload) {
  try {
    const section = payload["s:Envelope"]["s:Body"][0]["ExecuteResponse"][0]["ExecuteResult"][0]["a:Results"][0]["a:KeyValuePairOfstringanyType"]
    const props = section.reduce((obj, item) => {
      obj[item['c:key']] = item['c:value']
      return obj
    }, {})

    if (props.ValidationResult) {
        if (props.ValidationResult[0]['b:ValidationSuccess'][0] === "true") {
          // OK
          return {
            id: props.ValidationResult[0]['b:ActivityId'][0]
          }
        } else {
          if (props.Notifications) {
            // KO with a reason
            return {
              error: props.Notifications[0]['b:BusinessNotification'][0]['b:Message'][0]
            }
          } else {
            // KO without a reason
            return {
              error: 'Unknown error',
              raw: props
            }
          }
        }
    } else {
      return {
        error: 'Unexpected payload',
        raw: payload
      }
    }

  } catch (e) {
    return {
      error: 'Failure during payload process',
      raw: payload
    }
  }

}

function book(appointment) {


  const body = bookRequestTemplate(appointment)
  const options = {
    uri: `${process.env.HAUTS_DE_SEINE_ENDPOINT_ROOT}/XRMServices/2011/Organization.svc/web`,
    headers: {
      'ClientAppVersion': '9.0',
      'ClientAppName': 'WebClient',
      'SOAPAction': 'http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/Execute',
      'Accept': 'application/xml, text/xml, */*; q=0.01',
      'Content-Type': 'text/xml; charset=utf-8',
      'Cookie': process.env.HAUTS_DE_SEINE_COOKIE,
    },
    body: body
  }

  return rp(options).then(response => {
    return new Promise((resolve, reject) => {
      return parseString(response, function (err, result) {
        if (err) {
          return reject(err)
        }
        return resolve(result)  
      })
    })
  }).then(p => processResponse(p))
}


module.exports = {
  book,
  processResponse
}
