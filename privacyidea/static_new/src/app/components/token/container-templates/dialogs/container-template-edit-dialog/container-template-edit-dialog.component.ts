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

import {
  Component,
  inject,
  computed,
  linkedSignal,
  OnDestroy,
  AfterViewInit,
  ViewChild,
  ElementRef,
  Renderer2,
  signal
} from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";

import { FormsModule } from "@angular/forms";
import { MatButtonModule } from "@angular/material/button";
import { MatCardModule } from "@angular/material/card";
import { MatFormFieldModule } from "@angular/material/form-field";
import { MatIconModule } from "@angular/material/icon";
import { MatTooltipModule } from "@angular/material/tooltip";
import { MatInputModule } from "@angular/material/input";
import { MatCheckboxModule } from "@angular/material/checkbox";
import { MatListModule } from "@angular/material/list";
import {
  ContainerTemplateService,
  ContainerTemplateServiceInterface
} from "../../../../../services/container-template/container-template.service";
import { ContainerTemplate } from "../../../../../services/container/container.service";
import { PendingChangesService } from "../../../../../services/pending-changes/pending-changes.service";
import { deepCopy } from "../../../../../utils/deep-copy.utils";
import { SelectorButtonsComponent } from "@components/policies/dialogs/edit-policy-dialog/policy-panels/edit-action-tab/selector-buttons/selector-buttons.component";
import { ContainerTemplateAddTokenComponent } from "./container-template-add-token-chips/container-template-add-token.component";
import { TemplateAddedTokenRowComponent } from "./template-added-token-row/template-added-token-row.component";
import { TokenEnrollmentPayload } from "src/app/mappers/token-api-payload/_token-api-payload.mapper";
import { TokenTypeKey } from "src/app/services/token/token.service";
import { ROUTE_PATHS } from "../../../../../route_paths";

@Component({
  selector: "app-container-template-edit-dialog",
  standalone: true,
  imports: [
    MatInputModule,
    MatCardModule,
    MatIconModule,
    MatButtonModule,
    FormsModule,
    MatTooltipModule,
    MatFormFieldModule,
    MatListModule,
    MatCheckboxModule,
    SelectorButtonsComponent,
    ContainerTemplateAddTokenComponent,
    TemplateAddedTokenRowComponent
  ],
  templateUrl: "./container-template-edit-dialog.component.html",
  styleUrl: "./container-template-edit-dialog.component.scss"
})
export class ContainerTemplateEditDialogComponent implements AfterViewInit, OnDestroy {
  // --- Services ---
  readonly containerTemplateService: ContainerTemplateServiceInterface = inject(ContainerTemplateService);
  private readonly _pendingChangesService = inject(PendingChangesService);
  private readonly _router = inject(Router);
  private readonly _route = inject(ActivatedRoute);
  private readonly _renderer = inject(Renderer2);

  // --- View refs for sticky header ---
  @ViewChild("scrollContainer") scrollContainer!: ElementRef<HTMLElement>;
  @ViewChild("stickyHeader") stickyHeader!: ElementRef<HTMLElement>;
  @ViewChild("stickySentinel") stickySentinel!: ElementRef<HTMLElement>;
  private _observer!: IntersectionObserver;

  // --- Route param ---
  readonly templateName = signal("");

  // --- State Signals ---
  readonly originalTemplate = linkedSignal<ContainerTemplate[], ContainerTemplate | undefined>({
    source: () => this.containerTemplateService.templates(),
    computation: (templates) => {
      const name = this.templateName();
      if (!name) return undefined;
      return templates.find((t) => t.name === name);
    }
  });

  readonly template = linkedSignal<any, ContainerTemplate>({
    source: () => ({
      initialData: this.originalTemplate() ?? this.containerTemplateService.emptyContainerTemplate,
      defaultType: this.containerTemplateService.availableContainerTypes()[0] ?? ""
    }),
    computation: (source, previous) => {
      if (previous?.value && previous.value.name === source.initialData.name) {
        return previous.value;
      }
      const type = source.initialData.container_type || source.defaultType;
      return deepCopy({ ...source.initialData, container_type: type });
    }
  });

  constructor() {
    this._route.paramMap.pipe(takeUntilDestroyed()).subscribe((params) => {
      this.templateName.set(params.get("name") ?? "");
    });

    this._pendingChangesService.registerHasChanges(() => this.isDirty());
    this._pendingChangesService.registerSave(() => this.onSave());
    this._pendingChangesService.registerValidChanges(() => this.canSaveTemplate());
  }

  ngAfterViewInit(): void {
    if (!this.scrollContainer || !this.stickyHeader || !this.stickySentinel) return;
    this._observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.rootBounds) return;
        const shouldFloat = entry.boundingClientRect.top < entry.rootBounds.top;
        if (shouldFloat) {
          this._renderer.addClass(this.stickyHeader.nativeElement, "is-sticky");
        } else {
          this._renderer.removeClass(this.stickyHeader.nativeElement, "is-sticky");
        }
      },
      { root: this.scrollContainer.nativeElement, threshold: [0, 1] }
    );
    this._observer.observe(this.stickySentinel.nativeElement);
  }

  ngOnDestroy(): void {
    this._pendingChangesService.clearAllRegistrations();
    this._observer?.disconnect();
  }

  // --- Computed - General State ---
  readonly isNewTemplate = computed(() => !this.templateName());
  readonly title = computed(() =>
    this.isNewTemplate() ? $localize`New Container Template` : $localize`Edit Container Template`
  );
  readonly containerTypes = computed(() => this.containerTemplateService.availableContainerTypes());
  readonly containerTypesTitleCase = computed(() =>
    this.containerTemplateService.availableContainerTypes().map((type) => type.charAt(0).toUpperCase() + type.slice(1))
  );
  readonly availableTokenTypes = computed(() =>
    this.containerTemplateService.getTokenTypesForContainerType(this.template().container_type)
  );

  // --- Computed - Tokens ---
  readonly tokens = computed(() => this.template().template_options.tokens);
  readonly hasToken = computed(() => this.tokens().length > 0);

  // --- Computed - Validation & Conflict ---
  readonly nameConflict = computed(() =>
    this.containerTemplateService.templates().some((t) => t.name === this.template().name && t.name !== this.templateName())
  );
  readonly canSaveTemplate = computed<boolean>(() => {
    return this.containerTemplateService.canSaveTemplate(this.template()) && !this.nameConflict();
  });
  readonly isDirty = computed(() => {
    const base = this.originalTemplate() ?? this.containerTemplateService.emptyContainerTemplate;
    return JSON.stringify(this.template()) !== JSON.stringify(base);
  });
  readonly nameErrorMatcher = {
    isErrorState: () => this.nameConflict()
  };

  // --- Action Handling ---
  async onSave(): Promise<boolean> {
    if (!this.canSaveTemplate()) return false;

    const result = await this.containerTemplateService.postTemplateEdits(this.template());
    if (result) {
      const originalName = this.originalTemplate()?.name;
      if (originalName && originalName !== this.template().name) {
        await this.containerTemplateService.deleteTemplate(originalName);
      }
      this._pendingChangesService.clearAllRegistrations();
      this._router.navigateByUrl(ROUTE_PATHS.TOKENS_CONTAINERS_TEMPLATES);
    }
    return result;
  }

  onCancel(): void {
    this._router.navigateByUrl(ROUTE_PATHS.TOKENS_CONTAINERS_TEMPLATES);
  }

  // --- Data Modification Methods ---
  editTemplate(templateUpdates: Partial<ContainerTemplate>) {
    this.template.set({ ...this.template(), ...templateUpdates });
  }

  onAddToken(tokenType: string) {
    const updatedTokens = [...this.tokens(), { type: tokenType as TokenTypeKey }];
    this.updateTokens(updatedTokens);
  }

  onEditToken(patch: Partial<TokenEnrollmentPayload>, index: number) {
    const updatedTokens = this.tokens().map((token, i) => {
      if (i !== index) return token;
      const updatedToken = { ...token, ...patch };
      Object.keys(updatedToken).forEach((key) => {
        if (updatedToken[key] === undefined) {
          delete updatedToken[key]; // Remove undefined fields to avoid sending them in the API payload
        }
      });
      return updatedToken;
    });
    this.updateTokens(updatedTokens);
  }

  onDeleteToken(index: number) {
    this.updateTokens(this.tokens().filter((_, i) => i !== index));
  }

  // --- Private Helper Methods ---
  private updateTokens(tokens: TokenEnrollmentPayload[]) {
    this.editTemplate({
      template_options: {
        ...this.template().template_options,
        tokens
      }
    });
  }
}
