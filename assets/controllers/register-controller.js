// A Stimulus JavaScript controller file
// https://stimulus.hotwired.dev
// @see templates/security/login.html.twig
// More info on Symfony UX https://ux.symfony.com

import { Controller } from '@hotwired/stimulus';
import { register } from "@teamhanko/hanko-elements";

/*
 * The following line makes this controller "lazy": it won't be downloaded until needed
 * See https://github.com/symfony/stimulus-bridge#lazy-controllers
 */
/* stimulusFetch: 'lazy' */
export default class extends Controller {
  static targets = ['fullName', 'email', 'username']
  static values = {
    hankoApiUrl: String
  }

  async connect() {
    let { hanko } = await register(this.hankoApiUrlValue);
    let user = await hanko.user.getCurrent();
    let userEmail = user.email;

    this.usernameTarget.value = userEmail;
    this.emailTarget.value = userEmail;
  }
}
