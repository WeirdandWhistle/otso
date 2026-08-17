import * as db from "./databaseInteraction.js";

let env;
const interactionsPerClean = 25;
let interactionSinceLastClean = 0;
export function init(e){
    env = e;
}
export async function put(key, value, ttlSeconds){
    clean();
    // console.log(key,"save to KV",value);
    await db.putKV(env, key, JSON.stringify(value), ttlSeconds + Math.floor(Date.now()/1000));
}
export async function get(key){
    clean();
    const temp = await db.getKV(env, key);
    // console.log(key,"lookup from kv",temp);
    try {
        return JSON.parse(temp);
    } catch (error) {
        return null;
    }
}
export async function remove(key){
    await db.deleteKV(env, key);
    clean();
}
export async function clean(){
    interactionSinceLastClean++;
    if(interactionSinceLastClean <= interactionsPerClean){
        return;
    }
    interactionSinceLastClean = 0;
    await db.KVClean(env);
}