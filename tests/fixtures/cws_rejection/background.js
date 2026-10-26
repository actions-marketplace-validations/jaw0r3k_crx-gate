function executeDynamic(payload) {
  eval(payload);
  const fn = new Function("return 42");
  fn();
}
executeDynamic("console.log('pwn')");
