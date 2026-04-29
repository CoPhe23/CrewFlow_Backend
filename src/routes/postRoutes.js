const router = require("express").Router();
const auth = require("../middlewares/auth");
const ctrl = require("../controllers/postController");

router.post("/", auth, ctrl.createPost);
router.get("/events/:eventId/posts", auth, ctrl.getEventPosts);
router.delete("/:postId", auth, ctrl.deletePost);

module.exports = router;