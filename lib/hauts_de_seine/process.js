require('dotenv').config()
const moment = require('moment')
const { book } = require('./post')
const { fetch, fetchEntity } = require('./fetch')
const { runMiddleware } = require('../internal')

function get(attribute, query) {
  return async (req, res, next) => {
    try {
      const values = await Promise.all(req.input.data[attribute].map(a => fetchEntity(query(a))))
      req[attribute] = values
      req.steps.push(`${attribute} fetched: ✅`)
    } catch (e) {
      req.steps.push(`${attribute} fetch: ❌ (${e})`)
    }

    next()
  }
}

function ensureSingle(req, type) {
  const attribute = `${type}s`
  const ok = req[attribute].length == 1
  req.steps.push(`single ${type}: ${ok ? '✅' : `❌ (count: ${attribute.length}`}`)
  if (!ok) {
    throw req.steps[req.steps.length-1]
  }
}

const getAgents = get('agents', entity => `systemusers?$filter=domainname eq '${entity.email}'`)
const getUsers = get('users', entity => `contacts?$filter=emailaddress1 eq '${entity.email}'`)

const mapping = {
  cap_motif: {
    query: name => `cap_listemotifses?$filter=cap_name eq '${name}'`,
    id: 'cap_listemotifsid',
  },
  cap_sousmotif: {
    query: name => `cap_listemotifses?$filter=cap_name eq '${name}'`,
    id: 'cap_listemotifsid', 
  },
  mas_service: {
    query: name => `services?$filter=name eq '${name}'`,
    id: 'serviceid',
  },
  cap_centreid: {
    query: name => `cap_sites?$filter=cap_name eq '${name}'`,
    id: 'cap_siteid',
  },
  equipment: {
    query: name => `equipments?$filter=name eq '${name}'`,
    id: 'equipmentid',
  },
  ownerid: {
    query: name => `teams?$filter=name eq '${name}'`,
    id: 'ownerid',
  },
  new_test_tg_rdv_mapping: {
    query: name => `new_test_tg_rdv_mappings?$filter=new_test_tg_rdv_mapping1 eq '${name}'`,
    id: 'new_test_tg_rdv_mappingid'
  }
}

async function getSingle(req, type, value) {
  try {
    const escapedValue = value.replace("'", "''")
    const query = mapping[type].query(escapedValue)
    const result = await fetchEntity(query)

    const id = result[mapping[type].id]

    if (!id) {
      throw `Missing id field for ${type}`
    }

    req.steps.push(`${type} fetched: ✅`)
    return {
      id,
      raw: result,
    }
  } catch (e) {
    req.steps.push(`${type} fetch: ❌ (${e})`)
    throw e
  }
}

async function build(req, res, next) {
  await runMiddleware(req, res, getAgents)
  ensureSingle(req, 'agent')

  await runMiddleware(req, res, getUsers)
  ensureSingle(req, 'user')

  const rdv = req.input.data
  let start = moment(rdv.starts_at)
  const user = req.users[0].contactid
  const agent = req.agents[0].systemuserid

  let motif
  try {
    motif = await getSingle(req, 'new_test_tg_rdv_mapping', rdv.motif.name)
  } catch (e) {
    await fetch('new_test_tg_rdv_mappings', {
      new_test_tg_rdv_mapping1: rdv.motif.name
    })
    throw `Mapping for ${rdv.motif.name} empty`
  }

  const props = ['motif', 'sous_motif', 'service']
  props.forEach(p => {
    if (motif.raw[`_new_${p}_value`]) {
      req.steps.push(`${p}: ✅`)
    } else {
      req.steps.push(`${p}: ❌`)
      throw `Missing ${p} in mapping ${rdv.motif.name}`
    }
  })

  const appointment = {
    scheduledstart: start.format(),
    scheduledend: start.add(rdv.duration_in_min, 'minutes').format(),
    cap_demandeur: user,
    cap_beneficiaire: user,
    cap_professionnel: agent,
    cap_motif: motif.raw._new_motif_value,
    cap_sousmotif: motif.raw._new_sous_motif_value,
    mas_service: motif.raw._new_service_value,
  }
  try {
    req.response = await book(appointment)
  } catch (e) {
    req.response = {
      error: 'Failure when booking',
      raw: e,
    }
  }
}

module.exports = {
  build,
  getUsers
}
