const gg18 = require("../pkg");
const ethers = require("ethers");
const axios = require("axios");
const querystring = require("querystring");

var items = [{ idx: 0 }];

let threshold = 1;
let share = 2;
let addr = "http://127.0.0.1:8000";
let eigen_service = "http://127.0.0.1:3000";

const delay_ms = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const digest = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Hello Eigen"));

async function keygen(m, delay) {
  user_id = 315;
  key_name = "Just test";
  keygen_url = `${eigen_service}/tss/keygen`;
  res = await axios.post(
    keygen_url,
    querystring.stringify({ user_id: user_id, name: key_name, threshold: 1, share: 2 }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  let context = await m.gg18_keygen_client_new_context(addr, threshold, share, delay);
  console.log("keygen new context");

  console.time(1);
  round = 1;
  res = await axios.post(
    keygen_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log("test1");
  context = await m.gg18_keygen_client_round1(context, delay);
  console.log("test2");
  console.log("keygen round1:");
  console.log(res.data);
  console.timeEnd(1);

  return context;
  // console.time(2);
  // round = 2;
  // res = await axios.post(
  //   keygen_url,
  //   querystring.stringify({ user_id: user_id, round: round }),
  //   {
  //     headers: {
  //       "Content-Type": "application/x-www-form-urlencoded",
  //     },
  //   }
  // );

  
  // console.log("test3");
  
  // context = await m.gg18_keygen_client_round2(context, delay);
  // console.log("test4");
  // console.log("keygen round2: ");
  // console.log(res.data);
  // console.timeEnd(2);

  // console.time(3);
  // round = 3;
  // res = await axios.post(
  //   keygen_url,
  //   querystring.stringify({ user_id: user_id, round: round }),
  //   {
  //     headers: {
  //       "Content-Type": "application/x-www-form-urlencoded",
  //     },
  //   }
  // );
  // context = await m.gg18_keygen_client_round3(context, delay);
  // console.log("keygen round3: ");
  // console.log(res.data);
  // console.timeEnd(3);

  // console.time(4);
  // round = 4;
  // res = await axios.post(
  //   keygen_url,
  //   querystring.stringify({ user_id: user_id, round: round }),
  //   {
  //     headers: {
  //       "Content-Type": "application/x-www-form-urlencoded",
  //     },
  //   }
  // );
  // context = await m.gg18_keygen_client_round4(context, delay);
  // console.log("keygen round4: ");
  // console.log(res.data);
  // console.timeEnd(4);

  // console.time(5);
  // round = 5;
  // res = await axios.post(
  //   keygen_url,
  //   querystring.stringify({ user_id: user_id, round: round }),
  //   {
  //     headers: {
  //       "Content-Type": "application/x-www-form-urlencoded",
  //     },
  //   }
  // );
  // keygen_json = await m.gg18_keygen_client_round5(context, delay);
  // console.log("keygen json: ", keygen_json);
  // console.log(res.data);
  // console.timeEnd(5);

  // context = JSON.parse(context);
  // public_key_address = context["public_key_address"];
  // console.log("public_key_address: ", public_key_address);
  // return { keygen_json: keygen_json, public_key_address: public_key_address };
}

async function sign(m, key_store, delay, public_key_address) {
  console.log("public_key_address = ", public_key_address);
  user_id = 1;
  sign_url = `${eigen_service}/tss/sign`;
  res = await axios.post(
    sign_url,
    querystring.stringify({
      digest: digest.slice(2),
      user_address: public_key_address,
      user_id: user_id,
      threshold: 1,
      share: 2,
    }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  let context = await m.gg18_sign_client_new_context(
    addr,
    threshold,
    share,
    key_store,
    digest.slice(2)
  );
  console.log("sign new context: ", context);

  round = 0;
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round0(context, delay);
  console.log("sign round0: ");

  round = 1;
  console.time(1);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round1(context, delay);
  console.log("sign round1: ");
  console.timeEnd(1);

  round = 2;
  console.time(2);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round2(context, delay);
  console.log("sign round2: ");
  console.timeEnd(2);

  round = 3;
  console.time(3);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round3(context, delay);
  console.log("sign round3: ");
  console.timeEnd(3);

  round = 4;
  console.time(4);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round4(context, delay);
  console.log("sign round4: ");
  console.timeEnd(4);

  round = 5;
  console.time(5);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round5(context, delay);
  console.log("sign round5: ");
  console.timeEnd(5);

  round = 6;
  console.time(6);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round6(context, delay);
  console.log("sign round6: ");
  console.timeEnd(6);

  round = 7;
  console.time(7);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round7(context, delay);
  console.log("sign round7: ");
  console.timeEnd(7);

  round = 8;
  console.time(8);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  context = await m.gg18_sign_client_round8(context, delay);
  console.log("sign round8: ");
  console.timeEnd(8);

  round = 9;
  console.time(9);
  res = await axios.post(
    sign_url,
    querystring.stringify({ user_id: user_id, round: round }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  console.log(res.data);
  await delay_ms(50);

  sign_json = await m.gg18_sign_client_round9(context, delay);
  console.timeEnd(9);
  console.log("keysign json: ", sign_json);
  return sign_json;
}

async function main() {
  var results = await Promise.all(
    items.map(async (item) => {
      let delay = Math.max(Math.random() % 500, 100);
      let context = await keygen(gg18, delay);
      // let { keygen_json, public_key_address } = await keygen(gg18, delay);
      // return {
      //   idx: item.idx,
      //   res: keygen_json,
      //   public_key_address: public_key_address,
      // };
    })
  );

  // console.log("sign items: ", results);
  // await Promise.all(
  //   results.map(async (item) => {
  //     // if (item.idx < threshold + 1) {
  //       let delay = Math.max(Math.random() % 500, 100);
  //       //select random signer
  //       res = JSON.parse(
  //         await sign(gg18, item.res, delay, item.public_key_address)
  //       );
  //       console.log("Sign result: ", res);
  //       // recover the address
  //       console.log("digest", digest);
  //       let address = ethers.utils.recoverAddress(digest, {
  //         r: "0x" + res[0],
  //         s: "0x" + res[1],
  //         v: res[2],
  //       });
  //       console.log("recover address by etherjs", address);
  //     // }
  //   })
  // );
}

main().then(() => {
  console.log("Done");
});
