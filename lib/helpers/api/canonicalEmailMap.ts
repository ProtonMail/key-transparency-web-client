import { Api } from "../interfaces/Api";
import { SimpleMap } from "../interfaces/utils";
import { getCanonicalAddresses } from "./addresses";

enum API_CODES {
  GLOBAL_SUCCESS = 1001,
  SINGLE_SUCCESS = 1000,
}

interface GetCanonicalAddressesResponses {
  Email: string;
  Response: {
    Code: number;
    CanonicalEmail: string;
  };
}

interface GetCanonicalAddressesResponse {
  Code: number;
  Responses: GetCanonicalAddressesResponses[];
}

export const getCanonicalEmailMap = async (emails: string[] = [], api: Api) => {
  const map: SimpleMap<string> = {};
  if (emails.length) {
    const encodedEmails = emails.map((email) => encodeURIComponent(email));
    const { Responses, Code } = await api<GetCanonicalAddressesResponse>(
      getCanonicalAddresses(encodedEmails)
    );
    if (Code !== API_CODES.GLOBAL_SUCCESS) {
      throw new Error("Canonize operation failed");
    }
    Responses.forEach(({ Email, Response: { Code, CanonicalEmail } }) => {
      if (Code !== API_CODES.SINGLE_SUCCESS) {
        throw new Error("Canonize operation failed");
      }
      map[Email] = CanonicalEmail;
    });
  }
  return map;
};
