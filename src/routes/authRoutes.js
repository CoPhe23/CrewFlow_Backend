const router = require("express").Router();
const ctrl = require("../controllers/authController");
const auth = require("../middlewares/auth");

router.post("/register", ctrl.register);
router.post("/login", ctrl.login);
router.post("/forgot-password", ctrl.forgotPassword);
router.post("/reset-password", ctrl.resetPassword);
router.get("/me", auth, ctrl.me);

module.exports = router;