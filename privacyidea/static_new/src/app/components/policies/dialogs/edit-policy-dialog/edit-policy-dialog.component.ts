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

import { Component, computed, effect, inject, signal } from "@angular/core";
import { CommonModule } from "@angular/common";
import { ReactiveFormsModule } from "@angular/forms";
import { DialogWrapperComponent } from "../../../shared/dialog/dialog-wrapper/dialog-wrapper.component";
import { AbstractDialogComponent } from "../../../shared/dialog/abstract-dialog/abstract-dialog.component";
import { PolicyDetail, PolicyService, PolicyServiceInterface } from "../../../../services/policies/policies.service";
import { DialogAction } from "../../../../models/dialog";
import { PolicyPanelEditComponent } from "./policy-panels/policy-panel-edit/policy-panel-edit.component";
import { DialogService, DialogServiceInterface } from "src/app/services/dialog/dialog.service";
import {
  PendingChangesService,
  PendingChangesServiceInterface
} from "../../../../services/pending-changes/pending-changes.service";
import { ContentService, ContentServiceInterface } from "../../../../services/content/content.service";
import { ROUTE_PATHS } from "../../../../route_paths";
import { SaveAndExitDialogComponent } from "@components/shared/dialog/save-and-exit-dialog/save-and-exit-dialog.component";
import { NAVIGATION_ACCESSIBLE_DIALOG_CLASS } from "@components/constants/global.constants";

@Component({
  selector: "app-edit-policy-dialog",
  standalone: true,
  host: {
    class: NAVIGATION_ACCESSIBLE_DIALOG_CLASS
  },
  imports: [DialogWrapperComponent, CommonModule, ReactiveFormsModule, PolicyPanelEditComponent],
  templateUrl: "./edit-policy-dialog.component.html",
  styleUrl: "./edit-policy-dialog.component.scss"
})
export class EditPolicyDialogComponent extends AbstractDialogComponent<
  { policyDetail: PolicyDetail; mode: "edit" | "create" },
  Partial<PolicyDetail> | null
> {
  private readonly policyService: PolicyServiceInterface = inject(PolicyService);
  readonly dialogService: DialogServiceInterface = inject(DialogService);
  readonly pendingChangesService: PendingChangesServiceInterface = inject(PendingChangesService);
  readonly contentService: ContentServiceInterface = inject(ContentService);

  readonly policy = signal<PolicyDetail>(this.data.policyDetail);
  readonly policyEdits = signal<Partial<PolicyDetail>>({});
  readonly editedPolicy = computed(() => ({ ...this.policy(), ...this.policyEdits() }));
  readonly isPolicyEdited = computed(() => Object.keys(this.policyEdits()).length > 0);
  readonly mode = this.data.mode;

  readonly actions = computed<DialogAction<"submit" | null>[]>(() => [
    {
      label: this.mode === "create" ? $localize`Create Policy` : $localize`Save Changes`,
      value: "submit",
      type: "confirm",
      disabled: !this.canSave()
    }
  ]);

  constructor() {
    super();

    // Avoid closing the dialog with pending changes (when clicking next to the dialog or pressing ESC)
    if (this.dialogRef) {
      this.dialogRef.disableClose = true;
      this.dialogRef.backdropClick().subscribe(() => {
        this.close();
      });
      this.dialogRef.keydownEvents().subscribe((event) => {
        if (event.key === "Escape") {
          this.close();
        }
      });
    }

    this.pendingChangesService.registerHasChanges(() => this.isPolicyEdited());
    this.pendingChangesService.registerSave(this.savePolicy.bind(this));
    this.pendingChangesService.registerValidChanges(this.canSave.bind(this));

    // Close the dialog when navigating away from the events route
    // However, changing the route is disabled via the pendingChangesGuard when there are unsaved changes. This effect
    // will only be triggered when there are no unsaved changes or when the user confirmed discarding them.
    effect(() => {
      if (!this.contentService.routeUrl().startsWith(ROUTE_PATHS.POLICIES)) {
        super.close();
      }
    });
  }

  addPolicyEdit(edits: Partial<PolicyDetail>): void {
    this.policyEdits.set({ ...this.policyEdits(), ...edits });
  }

  canSave(): boolean {
    return this.isPolicyEdited() && !!this.editedPolicy().name?.trim();
  }

  onAction(value: "submit" | null): void {
    if (value !== "submit") return;
    this.savePolicy();
  }

  protected override close(): void {
    if (!this.isPolicyEdited()) {
      super.close();
      return;
    }

    this.dialogService.openDialog({
      component: SaveAndExitDialogComponent,
      data: {
        allowSaveExit: true,
        saveExitDisabled: !this.canSave()
      }
    }).afterClosed().subscribe((result) => {
      if (result === "save-exit") {
        this.savePolicy();
      } else if (result === "discard") {
        super.close();
      }
    });
  }

  async savePolicy() {
    let success = false;
    if (this.mode === "create") {
      success = await this.policyService.saveNewPolicy({ ...this.policy(), ...this.policyEdits() });
    } else {
      success = await this.policyService.savePolicyEdits(this.policy().name, { ...this.policy(), ...this.policyEdits() });
    }
    if (success) {
      super.close();
    }
    return success;
  }
}
