const router = require("express").Router();
const auth = require("../middlewares/auth");
const ctrl = require("../controllers/eventController");

router.get("/", auth, ctrl.getMyEvents);
router.post("/", auth, ctrl.createEvent);
router.post("/join", auth, ctrl.joinEvent);

router.get("/:eventId", auth, ctrl.getEventById);
router.patch("/:eventId", auth, ctrl.updateEvent);
router.delete("/:eventId", auth, ctrl.deleteEvent);
router.delete("/:eventId/leave", auth, ctrl.leaveEvent);

router.get("/:eventId/members", auth, ctrl.getEventMembers);
router.patch("/:eventId/members/:userId/promote", auth, ctrl.promoteMember);
router.delete("/:eventId/members/:userId", auth, ctrl.removeMember);

module.exports = router;