import emailQueue from "../queues/emailQueue.js";

const sendEmail = async ({ to, subject, html }) => {
  await emailQueue.add("send-email", {
    to,
    subject,
    html,
  });
};

export default sendEmail;
