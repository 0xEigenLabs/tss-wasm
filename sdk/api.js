const gg18 = require("../pkg");
const ethers = require("ethers");
const axios = require("axios");
const querystring = require("querystring");
const { v4: uuidv4 } = require("uuid");

const delay_ms = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function LocalTssNode(sm_addr, remote_addrs, t, n, uuid) {
  var o = new Object();

  if (remote_addrs.length != n - 1) {
    throw new Error("Remote addresses array should be equal to n - 1");
  }

  keygen_urls = remote_addrs.map(function (addr) {
    return `${addr}/tss/keygen`;
  });

  sign_urls = remote_addrs.map(function (addr) {
    return `${addr}/tss/sign`;
  });

  o.keygen = async function (uuid, key_name) {
    res = await Promise.all(
      keygen_urls.map(async function (keygen_url) {
        res = await axios.post(
          keygen_url,
          querystring.stringify({ user_id: uuid, name: key_name }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );

        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    let context = await m.gg18_keygen_client_new_context(sm_addr, t, n, delay);

    console.log("keygen new context: ");

    round = 1;
    res = await Promise.all(
      keygen_urls.map(async function (keygen_url) {
        res = await axios.post(
          keygen_url,
          querystring.stringify({ user_id: uuid, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_keygen_client_round1(context, delay);
    console.log("keygen round1:");

    round = 2;
    res = await Promise.all(
      keygen_urls.map(async function (keygen_url) {
        res = await axios.post(
          keygen_url,
          querystring.stringify({ user_id: uuid, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_keygen_client_round2(context, delay);
    console.log("keygen round2: ");

    round = 3;
    res = await Promise.all(
      keygen_urls.map(async function (keygen_url) {
        res = await axios.post(
          keygen_url,
          querystring.stringify({ user_id: uuid, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_keygen_client_round3(context, delay);
    console.log("keygen round3: ");

    round = 4;
    res = await Promise.all(
      keygen_urls.map(async function (keygen_url) {
        res = await axios.post(
          keygen_url,
          querystring.stringify({ user_id: uuid, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_keygen_client_round4(context, delay);
    console.log("keygen round4: ");

    round = 5;
    res = await Promise.all(
      keygen_urls.map(async function (keygen_url) {
        res = await axios.post(
          keygen_url,
          querystring.stringify({ user_id: uuid, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    keygen_json = await m.gg18_keygen_client_round5(context, delay);
    console.log("keygen json: ", keygen_json);
    context = JSON.parse(context);

    public_key_address = context["public_key_address"];
    console.log("public_key_address: ", public_key_address);
    return { keygen_json: keygen_json, public_key_address: public_key_address };
  };

  o.sign = async function (m, key_store, public_key_address) {
    console.log("public_key_address = ", public_key_address);
    user_id = 1;
    sign_url = `${eigen_service}/tss/sign`;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({
            digest: digest.slice(2),
            user_address: public_key_address,
            user_id: user_id,
          }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res.data);
    await delay_ms(1000);

    let context = await m.gg18_sign_client_new_context(
      addr,
      t,
      n,
      key_store,
      digest.slice(2)
    );
    console.log("sign new context: ", context);

    round = 0;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round0(context, delay);
    console.log("sign round0: ");

    round = 1;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round1(context, delay);
    console.log("sign round1: ");

    round = 2;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round2(context, delay);
    console.log("sign round2: ");

    round = 3;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round3(context, delay);
    console.log("sign round3: ");

    round = 4;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round4(context, delay);
    console.log("sign round4: ");

    round = 5;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round5(context, delay);
    console.log("sign round5: ");

    round = 6;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round6(context, delay);
    console.log("sign round6: ");

    round = 7;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round7(context, delay);
    console.log("sign round7: ");

    round = 8;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    context = await m.gg18_sign_client_round8(context, delay);
    console.log("sign round8: ");

    round = 9;
    res = await Promise.all(
      sign_urls.map(async function (sign_url) {
        res = await axios.post(
          sign_url,
          querystring.stringify({ user_id: user_id, round: round }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return res.data;
      })
    );

    // TODO: Remove this in product code
    console.log(res);
    await delay_ms(1000);

    sign_json = await m.gg18_sign_client_round9(context, delay);
    console.log("keysign json: ", sign_json);
    return sign_json;
  };

  return o;
}

function RemoteTssNode(sm_addr, port, t, n) {
  var o = new Object();

  return o;
}
