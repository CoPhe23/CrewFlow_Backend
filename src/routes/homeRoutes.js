const router = require("express").Router();
const auth = require("../middlewares/auth");
const ctrl = require("../controllers/homeController");

router.get("/", auth, ctrl.getHomepageData);

module.exports = router;