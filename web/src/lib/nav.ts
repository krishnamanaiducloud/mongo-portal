/** Full-page navigation for sign-in redirects (an object so tests can
 * observe it). */
export const browser = {
  assign(url: string) {
    window.location.assign(url);
  },
};
