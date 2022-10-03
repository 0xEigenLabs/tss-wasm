const thsig = import("./pkg");

var items = [{ idx: 0 }, { idx: 1 }, { idx: 2 }];
var results = [];

let t = 1;
let n = 3;
let addr = "http://127.0.0.1:8000"

const delay_ms = ms => new Promise(resolve => setTimeout(resolve, ms))

async function keygen(m, arg, delay) {
  let context = await m.gg18_keygen_client_new_context(addr, t, n, delay);
  console.log("keygen new context: ", context);
  context = await m.gg18_keygen_client_round1(context, delay);
  console.log("keygen round1: ", context);
  context = await m.gg18_keygen_client_round2(context, delay);
  console.log("keygen round2: ", context);
  context = await m.gg18_keygen_client_round3(context, delay);
  console.log("keygen round3: ", context);
  context = await m.gg18_keygen_client_round4(context, delay);
  console.log("keygen round4: ", context);
  keygen_json = await m.gg18_keygen_client_round5(context, delay);
  console.log("keygen json: ", keygen_json);
  return keygen_json;
}

async function sign(m, arg, key_store, delay) {
  let context = await m.gg18_sign_client_new_context(
    addr,
    t,
    n,
    key_store,
    "Hello Eigen"
  );
  console.log("sign new context: ", context);
  context = await m.gg18_sign_client_round0(context, delay);
  console.log("sign round0: ", context);
  context = await m.gg18_sign_client_round1(context, delay);
  console.log("sign round1: ", context);
  context = await m.gg18_sign_client_round2(context, delay);
  console.log("sign round2: ", context);
  context = await m.gg18_sign_client_round3(context, delay);
  console.log("sign round3: ", context);
  context = await m.gg18_sign_client_round4(context, delay);
  console.log("sign round4: ", context);
  context = await m.gg18_sign_client_round5(context, delay);
  console.log("sign round5: ", context);
  context = await m.gg18_sign_client_round6(context, delay);
  console.log("sign round6: ", context);
  context = await m.gg18_sign_client_round7(context, delay);
  console.log("sign round7: ", context);
  context = await m.gg18_sign_client_round8(context, delay);
  console.log("sign round8: ", context);
  sign_json = await m.gg18_sign_client_round9(context, delay);
  console.log("keygen json: ", sign_json);
  return sign_json;
}

/*
async function main() {
  const gg18 = await thsig;
  await Promise.all(
    items.map(
      async (item) => {
        let delay = Math.max(Math.random() % 500, 100);
        res = await keygen(gg18, item, delay);
        console.log("Keysign done", item.idx, " ", res);
        results.push(res);
      }
    )
  )

  await Promise.all(
    items.map(
      async (item) => {
        if (item.idx < t+1) {
          let delay = Math.max(Math.random() % 500, 100);
          delay_ms(delay);
          console.log(item.idx, " ", results[item.idx]);
          res = await sign(gg18, item, results[item.idx], delay + 1);
          console.log("Sign result: ", res);
        }
      }
    )
  )
}

main().then(() => {
  console.log("Done");
})
*/
thsig.then((m) => {
  items.forEach(async function (item) {
    let delay = Math.max(Math.random() % 500, 100);
    res = await keygen(m, item, delay);
    console.log(item.idx, " ", res);
    results.push(res);

    if (results.length == items.length) {
      console.log(results.length);
      items.forEach(async function (item) {
        if (item.idx < t + 1) {
          console.log(item.idx, " ", results[item.idx]);
          let delay = Math.max(Math.random() % 500, 100);
          res = await sign(m, item, results[item.idx], delay);
          console.log("Sign result: ", res);
        }
      });
    }
  });
});
