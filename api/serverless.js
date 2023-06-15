const path = require("path");
const fastify = require("fastify");
const static = require("fastify-static");
const extractSSCHeaders = require("../utils/sscHelpers");
const { SSC } = require('@securityscorecard/sdk');
const dns = require('dns');

require('dotenv').config();

const server = fastify({
  logger: true,
});

const TOKEN = process.env.SSC_API_TOKEN;

const ssc = SSC({ token: TOKEN, host: 'https://platform-api.securityscorecard.tech' });

async function readTxtRecords(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(domain, (err, records) => {
      if (err) {
        console.error('Error retrieving DNS TXT records:', err);
        reject(err);
      } else {
        var out = "";
        console.log('DNS TXT records for', domain);
        records.forEach((record, index) => {
          out += `Record ${index + 1}: ` + record.join(', ');
          console.log(`Record ${index + 1}:`, record.join(', '))
        });
        resolve(out);
      }
    });
  });
}

server.get('/', async (request, reply) => {
  try {
    let txtRecords = await readTxtRecords(process.env.TARGET_DOMAIN)
    reply.send(txtRecords)
  } catch (err) {
    reply.code(500).send({ error: 'Could not fetch TXT records' });
  }
});

// this is an event that could be dispatched by a custom event, 
// for the sole purpose of the example, it will be propagated using a post event
server.post('/signal', async(request, reply) => {
  try {
    let txtRecords = await readTxtRecords(process.env.TARGET_DOMAIN);
    const signalResponse = await ssc.apps.sendSignals('signal_app.sample_information', [
      { domain: process.env.TARGET_DOMAIN, summary: 'TXT Records found: ' + txtRecords, }]);
    reply.send(signalResponse);
  } catch (error) {
    reply.send(error);
  }
});

server.get('/more-info', async (request, reply) => reply.send("Lists all TXT records in a domain"));

server.register(static, {
  root: path.join(__dirname, '..', 'public'),
  prefix: '/public/',
});

const start = async () => await server.listen(3000);

start();