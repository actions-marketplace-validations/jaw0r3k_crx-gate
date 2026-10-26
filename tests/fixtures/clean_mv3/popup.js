document.addEventListener('DOMContentLoaded', async () => {
  const result = await chrome.storage.local.get(['duration']);
  console.log("Timer loaded", result);
});
