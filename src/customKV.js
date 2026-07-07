const KV = new Map();
const interactionsPerClean = 25;
let interactionSinceLastClean = 0; 
export function put(key, value, ttl){
    clean();
    KV.set(key, {ttl: ttl+Date.now(), data: value});
}
export function get(key){
    clean();
    const value = KV.get(key);
    if(value.ttl >= Date.now()){
        KV.delete(key);
        return null;
    }
    return value.data;
}
export function remove(key){
    KV.delete(key);
    clean();
}
export function clean(){
    interactionSinceLastClean++;
    if(interactionSinceLastClean <= interactionsPerClean){
        return;
    }
    const iterator = KV.entries();
    const now = Date.now();
    let value = iterator.next().value;
    while(value){
        if(value[1].ttl <= now){
            KV.delete(value[0]);
        }
    }
}