const router = require("express").Router();
const auth = require("../middlewares/auth");
const ctrl = require("../controllers/messageController");

router.post("/", auth, ctrl.sendMessage);
router.get("/events/:eventId/messages", auth, ctrl.getMessages);

module.exports = router;