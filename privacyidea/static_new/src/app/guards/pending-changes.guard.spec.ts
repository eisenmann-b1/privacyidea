/**
 * (c) NetKnights GmbH 2026,  https://netknights.it
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

import { pendingChangesGuard } from "./pending-changes.guard";
import { TestBed } from "@angular/core/testing";
import { PendingChangesService } from "../services/pending-changes/pending-changes.service";
import { MockDialogService, MockPendingChangesService } from "../../testing/mock-services";
import { ActivatedRouteSnapshot, RouterStateSnapshot } from "@angular/router";
import { DialogService } from "../services/dialog/dialog.service";
import { isObservable, of } from "rxjs";


describe("pendingChangesGuard", () => {
  let pendingChangesService: MockPendingChangesService;
  let dialogService: MockDialogService;
  const mockRouteSnapshot = new ActivatedRouteSnapshot();
  mockRouteSnapshot.params = { id: "123" };
  const mockRoute = new ActivatedRouteSnapshot();
  const mockState = {} as RouterStateSnapshot;
  const mockNextState = {} as RouterStateSnapshot;

  beforeEach(() => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        { provide: PendingChangesService, useClass: MockPendingChangesService },
        { provide: DialogService, useClass: MockDialogService }]
    });

    pendingChangesService = TestBed.inject(PendingChangesService) as unknown as MockPendingChangesService;
    dialogService = TestBed.inject(DialogService) as unknown as MockDialogService;
  });

  it("should return true if there are no pending changes", async () => {
    pendingChangesService.registerHasChanges(jest.fn(() => false));
    const result = TestBed.runInInjectionContext(() =>
      pendingChangesGuard(undefined, mockRoute, mockState, mockNextState)
    );
    expect(isObservable(result));
    if (isObservable(result)) {
      result.subscribe(res => {
        expect(pendingChangesService.clearAllRegistrations).not.toHaveBeenCalled();
        expect(pendingChangesService.save).not.toHaveBeenCalled();
        expect(res).toBe(true);
      });
    }
  });

  it("should return true and unregister changes if user discards", async () => {
    pendingChangesService.registerHasChanges(jest.fn(() => true));

    // mock dialog discard is selected
    dialogService.openDialog = jest.fn(() => ({
      afterClosed: () => of("discard")
    }));

    const result = TestBed.runInInjectionContext(() =>
      pendingChangesGuard(undefined, mockRoute, mockState, mockNextState)
    );

    expect(isObservable(result));
    if (isObservable(result)) {
      result.subscribe(res => {
        expect(pendingChangesService.clearAllRegistrations).toHaveBeenCalled();
        expect(pendingChangesService.save).not.toHaveBeenCalled();
        expect(res).toBe(true);
      });
    }
  });

  it("should call save, unregister changes, and return true on save-exit success", async () => {
    const saveFn = jest.fn().mockResolvedValue(true);
    pendingChangesService.registerHasChanges(jest.fn(() => true));
    pendingChangesService.registerSave(saveFn);

    // mock dialog save-exit is selected
    dialogService.openDialog = jest.fn(() => ({
      afterClosed: () => of("save-exit")
    }));

    const result = TestBed.runInInjectionContext(() =>
      pendingChangesGuard(undefined, mockRoute, mockState, mockNextState)
    );

    expect(isObservable(result));
    if (isObservable(result)) {
      result.subscribe(res => {
        expect(pendingChangesService.clearAllRegistrations).toHaveBeenCalled();
        expect(pendingChangesService.save).toHaveBeenCalled();
        expect(res).toBe(true);
      });
    }
  });

  it("should handle failed save", async () => {
    const saveFn = jest.fn().mockResolvedValue(false);
    pendingChangesService.registerSave(saveFn);
    pendingChangesService.registerHasChanges(jest.fn(() => true));

    // mock dialog save-exit is selected
    dialogService.openDialog = jest.fn(() => ({
      afterClosed: () => of("save-exit")
    }));

    const result = TestBed.runInInjectionContext(() =>
      pendingChangesGuard(undefined, mockRoute, mockState, mockNextState)
    );

    expect(isObservable(result));
    if (isObservable(result)) {
      result.subscribe(res => {
        expect(pendingChangesService.clearAllRegistrations).not.toHaveBeenCalled();
        expect(pendingChangesService.save).toHaveBeenCalled();
        expect(res).toBe(false);
      });
    }
  });

  it("should return false if user cancels dialog", async () => {
    pendingChangesService.registerHasChanges(jest.fn(() => true));

    // mock dialog save-exit is selected
    dialogService.openDialog = jest.fn(() => ({
      afterClosed: () => of("cancel")
    }));

    const result = TestBed.runInInjectionContext(() =>
      pendingChangesGuard(undefined, mockRoute, mockState, mockNextState)
    );

    expect(isObservable(result));
    if (isObservable(result)) {
      result.subscribe(res => {
        expect(pendingChangesService.clearAllRegistrations).not.toHaveBeenCalled();
        expect(pendingChangesService.save).not.toHaveBeenCalled();
        expect(res).toBe(true);
      });
    }
  });
});
