import { PaginationParams } from "./interface";

export const queryAddresses = (params?: PaginationParams) => ({
  url: "addresses",
  method: "get",
  params,
});

export const getCanonicalAddresses = (Emails: string[]) => ({
  // params doesn't work correctly so
  url: `addresses/canonical?${Emails.map((email) => `Emails[]=${email}`).join(
    "&"
  )}`,
  method: "get",
  // params: { Emails },
});
