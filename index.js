// @ts-check
import init, { bcrypt_hash2 } from "./pkg/calc_bcrypt_webasm.js";

const run = async () => {
  await init();
  let hash = bcrypt_hash2("foobarbaz", 4);
  console.log(`Hash: ${hash}`);
  return hash;
};

run().catch((e) => {
  console.log(`exception: ${e}`);
});
