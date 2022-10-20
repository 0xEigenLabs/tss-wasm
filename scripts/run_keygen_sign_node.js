const gg18 = require('../pkg')
const ethers = require('ethers')

var items = [{ idx: 0 }, { idx: 1 }, { idx: 2 }]

let t = 1
let n = 3
let addr = 'http://127.0.0.1:8000'

const delay_ms = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const digest = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('Hello Eigen'))

async function keygen(m, delay) {
  let context = await m.gg18_keygen_client_new_context(addr, t, n, delay)
  console.log('keygen new context: ')
  context = await m.gg18_keygen_client_round1(context, delay)
  console.log('keygen round1:')
  context = await m.gg18_keygen_client_round2(context, delay)
  console.log('keygen round2: ')
  context = await m.gg18_keygen_client_round3(context, delay)
  console.log('keygen round3: ')
  context = await m.gg18_keygen_client_round4(context, delay)
  console.log('keygen round4: ')
  keygen_json = await m.gg18_keygen_client_round5(context, delay)
  console.log('keygen json: ', keygen_json)
  return keygen_json
}

async function sign(m, key_store, delay) {
  let context = await m.gg18_sign_client_new_context(
    addr,
    t,
    n,
    key_store,
    digest.slice(2)
  )
  console.log('sign new context: ', context)
  context = await m.gg18_sign_client_round0(context, delay)
  console.log('sign round0: ')
  context = await m.gg18_sign_client_round1(context, delay)
  console.log('sign round1: ')
  context = await m.gg18_sign_client_round2(context, delay)
  console.log('sign round2: ')
  context = await m.gg18_sign_client_round3(context, delay)
  console.log('sign round3: ')
  context = await m.gg18_sign_client_round4(context, delay)
  console.log('sign round4: ')
  context = await m.gg18_sign_client_round5(context, delay)
  console.log('sign round5: ')
  context = await m.gg18_sign_client_round6(context, delay)
  console.log('sign round6: ')
  context = await m.gg18_sign_client_round7(context, delay)
  console.log('sign round7: ')
  context = await m.gg18_sign_client_round8(context, delay)
  console.log('sign round8: ')
  sign_json = await m.gg18_sign_client_round9(context, delay)
  console.log('keysign json: ', sign_json)
  return sign_json
}

async function main() {
  var results = await Promise.all(
    items.map(async (item) => {
      let delay = Math.max(Math.random() % 500, 100)
      res = await keygen(gg18, delay)
      return { idx: item.idx, res: res }
    }),
  )

  console.log('sign items: ', results)
  await Promise.all(
    results.map(async (item) => {
      if (item.idx < t + 1) {
        let delay = Math.max(Math.random() % 500, 100)
        //select random signer
        res = JSON.parse(await sign(gg18, item.res, delay))
        console.log('Sign result: ', res)
        // recover the address
        console.log("digest", digest);
        let address = ethers.utils.recoverAddress(digest, {
          r: "0x"+res[0],
          s: "0x"+res[1],
          v: res[2]
        })
        console.log("recover address by etherjs", address)
      }
    }),
  )
}

main().then(() => {
  console.log('Done')
})
