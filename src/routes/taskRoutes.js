const router = require("express").Router();
const auth = require("../middlewares/auth");
const ctrl = require("../controllers/taskController");

router.post("/", auth, ctrl.createTask);
router.get("/events/:eventId/tasks", auth, ctrl.getEventTasks);
router.patch("/:taskId/complete", auth, ctrl.completeTask);

module.exports = router;