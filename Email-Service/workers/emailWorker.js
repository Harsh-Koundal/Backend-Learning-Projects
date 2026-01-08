import "dotenv/config";
import { Worker } from "bullmq";
import redis from "../config/redis.js";
import transporter from "../config/email.js";

const emailWorker = new Worker(
    "emailQueue",
    async(job)=>{
        const {to,subject,html} = job.data;

        await transporter.sendMail({
            from:`"Auth Service" <${process.env.EMAIL_USER}>`,
            to,
            subject,
            html,
        });
    },
    {
        connection:redis,
    }
);

emailWorker.on("completed",(job)=>{
    console.log(`📧 Email sent: Job ${job.id}`);
});

emailWorker.on("failed", (job, err) => {
  console.error(`❌ Email failed: Job ${job.id}`, err);
})