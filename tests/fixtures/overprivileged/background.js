chrome.tabs.query({}, (tabs) => {
  const count = tabs.length;
  // Tab ID is accessed, but not sensitive tab.url or tab.title
  tabs.forEach(tab => console.log("Tab id: " + tab.id));
  chrome.action.setBadgeText({ text: String(count) });
});
