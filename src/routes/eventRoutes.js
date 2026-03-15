const router = require("express").Router();
const auth = require("../middlewares/auth");
const ctrl = require("../controllers/eventController");

router.get("/", auth, ctrl.getMyEvents);
router.post("/", auth, ctrl.createEvent);
router.post("/join", auth, ctrl.joinEvent);

module.exports = router;