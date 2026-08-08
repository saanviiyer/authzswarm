import { Checker } from "../types";
import { securityHeadersChecker } from "./securityHeaders";
import { cookiesChecker } from "./cookies";
import { reflectedXssChecker } from "./reflectedXss";
import { exposedPathsChecker } from "./exposedPaths";
import { directoryListingChecker } from "./directoryListing";
import { tlsChecker } from "./tls";
import { verboseErrorsChecker } from "./verboseErrors";
import { openRedirectChecker } from "./openRedirect";

/**
 * The swarm. Each checker is a specialized, independent agent that probes one
 * class of common, well-known web issue. They run concurrently (bounded by the
 * HTTP client's throttle) and each returns structured findings.
 */
export const CHECKERS: Checker[] = [
  securityHeadersChecker,
  cookiesChecker,
  reflectedXssChecker,
  exposedPathsChecker,
  directoryListingChecker,
  tlsChecker,
  verboseErrorsChecker,
  openRedirectChecker,
];
