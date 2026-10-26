chrome.alarms.onAlarm.addListener(async (alarm) => {
  await chrome.storage.local.set({ lastTick: Date.now() });
});
