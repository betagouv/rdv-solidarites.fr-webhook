const rp = require('request-promise')

function fetch(item, body) {
  let options = {
    uri: `${process.env.HAUTS_DE_SEINE_ENDPOINT_ROOT}${process.env.HAUTS_DE_SEINE_ENDPOINT_PATH}${item}`,
    headers: {
      "OData-MaxVersion": "4.0",
      "OData-Version": "4.0",
      "Accept": "application/json",
      "Content-Type": "application/json; charset=utf-8",
      'Cookie': process.env.HAUTS_DE_SEINE_COOKIE,
    },
    json: true,
    resolveWithFullResponse: true
  }

  if (body) {
    options.method = 'POST'
    options.body = body
  }

  return rp(options)
  .catch(function (err) {
    console.log("err")//.message)
    console.log(err.error)//.message)
    return err
  })
}

async function fetchEntity(query) {
  const response = await fetch(query)
  switch (response.body.value.length) {
    case 0:
      throw `No matches for ${query}`
    case 1:
      return response.body.value[0]
      break
    default:
      throw `Multiple matches for ${query}`
  }
}

module.exports = {
  fetch,
  fetchEntity,
}
