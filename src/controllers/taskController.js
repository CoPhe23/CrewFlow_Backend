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

  return {
    id: snap.docs[0].id,
    ...snap.docs[0].data(),
  };
}

function buildMapsUrl(address, location) {
  const query = address || location || "";

  if (!query.trim()) return "";

  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(query.trim())}`;
}

exports.createTask = async (req, res) => {
  try {
    const {
      eventId,
      title,
      description,
      location,
      address,
      mapsUrl,
      start,
      end,
      category,
      color,
      assignedTo,
    } = req.body;

    const userId = req.user.userId;

    if (!eventId || !title || !title.trim()) {
      return res.status(400).json({ error: "A cím kötelező." });
    }

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Nem vagy tagja ennek az eseménynek." });
    }

    if (membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin hozhat létre beosztás blokkot." });
    }

    if (assignedTo) {
      const assignedMembership = await getMembership(eventId, assignedTo);

      if (!assignedMembership) {
        return res.status(400).json({
          error: "A kiválasztott felelős nem tagja az eseménynek.",
        });
      }
    }

    const taskId = crypto.randomUUID();

    const finalAddress = address?.trim() || "";
    const finalLocation = location?.trim() || "";
    const finalMapsUrl = mapsUrl?.trim() || buildMapsUrl(finalAddress, finalLocation);

    const task = {
      id: taskId,
      eventId,
      title: title.trim(),
      category: category?.trim() || "Feladat",
      start: start?.trim() || "",
      end: end?.trim() || "",
      location: finalLocation,
      address: finalAddress,
      mapsUrl: finalMapsUrl,
      description: description?.trim() || "",
      color: color || "green",
      assignedTo: assignedTo || null,
      createdBy: userId,
      status: "OPEN",
      createdAt: new Date().toISOString(),
    };

    await db.collection("tasks").doc(taskId).set(task);

    return res.status(201).json({
      message: "Beosztás blokk létrehozva.",
      task,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Nem sikerült létrehozni a blokkot." });
  }
};

exports.getEventTasks = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Nem vagy tagja ennek az eseménynek." });
    }

    const snap = await db.collection("tasks").where("eventId", "==", eventId).get();

    const tasks = snap.docs
      .map((doc) => doc.data())
      .sort((a, b) => {
        const aTime = a.start || "";
        const bTime = b.start || "";
        return aTime.localeCompare(bTime);
      });

    return res.json(tasks);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Nem sikerült betölteni a beosztást." });
  }
};

exports.updateTask = async (req, res) => {
  try {
    const { taskId } = req.params;
    const userId = req.user.userId;

    const {
      title,
      description,
      location,
      address,
      mapsUrl,
      start,
      end,
      category,
      color,
      assignedTo,
    } = req.body;

    const taskDoc = await db.collection("tasks").doc(taskId).get();

    if (!taskDoc.exists) {
      return res.status(404).json({ error: "A blokk nem található." });
    }

    const task = taskDoc.data();

    const membership = await getMembership(task.eventId, userId);

    if (!membership || membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin szerkesztheti a blokkot." });
    }

    if (!title || !title.trim()) {
      return res.status(400).json({ error: "A cím kötelező." });
    }

    if (assignedTo) {
      const assignedMembership = await getMembership(task.eventId, assignedTo);

      if (!assignedMembership) {
        return res.status(400).json({
          error: "A kiválasztott felelős nem tagja az eseménynek.",
        });
      }
    }

    const finalAddress = address?.trim() || "";
    const finalLocation = location?.trim() || "";
    const finalMapsUrl = mapsUrl?.trim() || buildMapsUrl(finalAddress, finalLocation);

    await db.collection("tasks").doc(taskId).update({
      title: title.trim(),
      description: description?.trim() || "",
      location: finalLocation,
      address: finalAddress,
      mapsUrl: finalMapsUrl,
      start: start?.trim() || "",
      end: end?.trim() || "",
      category: category?.trim() || "Feladat",
      color: color || "green",
      assignedTo: assignedTo || null,
      updatedAt: new Date().toISOString(),
    });

    return res.json({ message: "Blokk frissítve." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Nem sikerült frissíteni a blokkot." });
  }
};

exports.completeTask = async (req, res) => {
  try {
    const { taskId } = req.params;
    const userId = req.user.userId;

    const taskDoc = await db.collection("tasks").doc(taskId).get();

    if (!taskDoc.exists) {
      return res.status(404).json({ error: "A blokk nem található." });
    }

    const task = taskDoc.data();

    const membership = await getMembership(task.eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Nem vagy tagja ennek az eseménynek." });
    }

    const isAdmin = membership.role === "ADMIN";
    const isAssignedUser = task.assignedTo === userId;

    if (!isAdmin && !isAssignedUser) {
      return res.status(403).json({ error: "Ezt a blokkot nem állíthatod készre." });
    }

    await db.collection("tasks").doc(taskId).update({
      status: "DONE",
      completedAt: new Date().toISOString(),
      completedBy: userId,
    });

    return res.json({ message: "Blokk készre állítva." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Nem sikerült készre állítani." });
  }
};

exports.reopenTask = async (req, res) => {
  try {
    const { taskId } = req.params;
    const userId = req.user.userId;

    const taskDoc = await db.collection("tasks").doc(taskId).get();

    if (!taskDoc.exists) {
      return res.status(404).json({ error: "A blokk nem található." });
    }

    const task = taskDoc.data();

    const membership = await getMembership(task.eventId, userId);

    if (!membership || membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin nyithatja vissza a blokkot." });
    }

    await db.collection("tasks").doc(taskId).update({
      status: "OPEN",
      completedAt: null,
      completedBy: null,
      updatedAt: new Date().toISOString(),
    });

    return res.json({ message: "Blokk visszanyitva." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Nem sikerült visszanyitni." });
  }
};

exports.deleteTask = async (req, res) => {
  try {
    const { taskId } = req.params;
    const userId = req.user.userId;

    const taskDoc = await db.collection("tasks").doc(taskId).get();

    if (!taskDoc.exists) {
      return res.status(404).json({ error: "A blokk nem található." });
    }

    const task = taskDoc.data();

    const membership = await getMembership(task.eventId, userId);

    if (!membership || membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin törölheti a blokkot." });
    }

    await db.collection("tasks").doc(taskId).delete();

    return res.json({ message: "Blokk törölve." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Nem sikerült törölni a blokkot." });
  }
};