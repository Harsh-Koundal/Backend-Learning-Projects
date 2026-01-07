import {Redis} from "ioredis";

const redis = new Redis({
    host:process.env.REDIS_HOSt,
    port:process.env.REDIS_PORT,
    maxRetriesPerRequest:null,
});

export default redis;