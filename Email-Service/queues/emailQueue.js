import {Queue} from "bullmq";
import redis from "../config/redis.js";

const emailQueue = new Queue("emailQueue",{
    connection:redis,
});

export default emailQueue;