/**
 * (c) NetKnights GmbH 2025,  https://netknights.it
 *
 * This code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 **/
import { HttpErrorResponse, httpResource, HttpResourceRef } from "@angular/common/http";
import { PiResponse } from "../../app.component";
import { effect, inject, Injectable } from "@angular/core";
import { ROUTE_PATHS } from "../../route_paths";
import { AuthService, AuthServiceInterface } from "../auth/auth.service";
import { ContentService, ContentServiceInterface } from "../content/content.service";
import { environment } from "../../../environments/environment";
import { NotificationService } from "../notification/notification.service";

export interface ClientData {
  hostname?: string;
  ip?: string;
  lastseen?: string;
  application?: string;
}

export type ClientsDict = Record<string, ClientData[]>;

export interface ClientsServiceInterface {
  clientsResource: HttpResourceRef<PiResponse<ClientsDict> | undefined>;
}

@Injectable({
  providedIn: "root"
})
export class ClientsService implements ClientsServiceInterface {
  private readonly authService: AuthServiceInterface = inject(AuthService);
  private readonly contentService: ContentServiceInterface = inject(ContentService);
  private readonly notificationService = inject(NotificationService);
  private clientsBaseUrl = environment.proxyUrl + "/client/";

  constructor() {
    effect(() => {
      if (this.clientsResource.error()) {
        const err = this.clientsResource.error() as HttpErrorResponse;
        console.error("Failed to get clients.", err.message);
        const message = err.error?.result?.error?.message || err.message;
        this.notificationService.openSnackBar("Failed to get clients. " + message);
      }
    });
  }

  clientsResource = httpResource<PiResponse<ClientsDict>>(() => {
    if (this.contentService.routeUrl() !== ROUTE_PATHS.CLIENTS || !this.authService.actionAllowed("clienttype")) {
      return undefined;
    }
    return {
      url: this.clientsBaseUrl,
      method: "GET",
      headers: this.authService.getHeaders(),
      params: {}
    };
  });

}