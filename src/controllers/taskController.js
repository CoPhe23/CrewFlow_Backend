const { db } = require("../lib/firebase");
const crypto = require("crypto");

async function getMembership(eventId, userId) {
  const snap = await db
    .collection("event_members")
    .where("eventId", "==", eventId)
    .where("userId", "==", userId)
    .limit(1)
    .get();

  if (snap.empty) return null;
  return snap.docs[0].data();
}

exports.createTask = async (req, res) => {
  try {
    const { eventId, title, description, location, assignedTo } = req.body;
    const userId = req.user.userId;

    if (!title || !eventId) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "You are not a member of this event" });
    }

    if (membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Only admins can create tasks" });
    }

    if (assignedTo) {
      const assignedMembership = await getMembership(eventId, assignedTo);
      if (!assignedMembership) {
        return res.status(400).json({ error: "Assigned user is not a member of this event" });
      }
    }

    const taskId = crypto.randomUUID();

    await db.collection("tasks").doc(taskId).set({
      id: taskId,
      eventId,
      title: title.trim(),
      description: description?.trim() || "",
      location: location?.trim() || "",
      assignedTo: assignedTo || null,
      createdBy: userId,
      status: "OPEN",
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: "Task created",
      taskId,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Task creation failed" });
  }
};

exports.getEventTasks = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "You are not a member of this event" });
    }

    const snap = await db
      .collection("tasks")
      .where("eventId", "==", eventId)
      .get();

    const tasks = snap.docs.map((doc) => doc.data());

    return res.json(tasks);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Fetch tasks failed" });
  }
};

exports.completeTask = async (req, res) => {
  try {
    const { taskId } = req.params;
    const userId = req.user.userId;

    const taskDoc = await db.collection("tasks").doc(taskId).get();

    if (!taskDoc.exists) {
      return res.status(404).json({ error: "Task not found" });
    }

    const task = taskDoc.data();

    const membership = await getMembership(task.eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "You are not a member of this event" });
    }

    const isAdmin = membership.role === "ADMIN";
    const isAssignedUser = task.assignedTo === userId;

    if (!isAdmin && !isAssignedUser) {
      return res.status(403).json({ error: "You cannot complete this task" });
    }

    await db.collection("tasks").doc(taskId).update({
      status: "DONE",
      completedAt: new Date().toISOString(),
      completedBy: userId,
    });

    return res.json({
      message: "Task completed",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Task update failed" });
  }
};