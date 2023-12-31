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
  static targets = ['hankoAuth']
  static values = {
    hankoApiUrl: String,
    lastUsername: String,
    redirectTo: String,
    loginPath: String
  }

  async connect() {
    let { hanko } = await register(this.hankoApiUrlValue);

    hanko.onAuthFlowCompleted(async (authFlowCompletedDetail) => {
      window.location = this.loginPathValue;
    })
  }
}
