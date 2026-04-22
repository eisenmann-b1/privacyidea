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

import { ComponentFixture, TestBed } from "@angular/core/testing";
import { NoopAnimationsModule } from "@angular/platform-browser/animations";
import { provideHttpClient } from "@angular/common/http";
import { provideHttpClientTesting } from "@angular/common/http/testing";
import { ActivatedRoute, Router, convertToParamMap } from "@angular/router";
import { BehaviorSubject } from "rxjs";
import { ContainerTemplateService } from "../../../../../services/container-template/container-template.service";
import { MockContainerTemplateService } from "../../../../../../testing/mock-services/mock-container-template-service";
import { ContainerTemplateEditDialogComponent } from "./container-template-edit-dialog.component";
import { PendingChangesService } from "src/app/services/pending-changes/pending-changes.service";
import { MockPendingChangesService, MockRouter } from "src/testing/mock-services";
import { ROUTE_PATHS } from "../../../../../route_paths";
import { ContainerTemplate } from "../../../../../services/container/container.service";

describe("ContainerTemplateEditDialogComponent", () => {
  let component: ContainerTemplateEditDialogComponent;
  let fixture: ComponentFixture<ContainerTemplateEditDialogComponent>;
  let containerTemplateServiceMock: MockContainerTemplateService;
  let mockRouter: MockRouter;
  let paramMap$: BehaviorSubject<ReturnType<typeof convertToParamMap>>;

  const existingTemplate: ContainerTemplate = {
    name: "ExistingTemplate",
    container_type: "smartphone",
    default: false,
    template_options: { tokens: [] }
  };

  function createFixture() {
    fixture = TestBed.createComponent(ContainerTemplateEditDialogComponent);
    component = fixture.componentInstance;
    mockRouter = TestBed.inject(Router) as unknown as MockRouter;
    fixture.detectChanges();
  }

  beforeEach(async () => {
    paramMap$ = new BehaviorSubject(convertToParamMap({}));

    await TestBed.configureTestingModule({
      imports: [ContainerTemplateEditDialogComponent, NoopAnimationsModule],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ContainerTemplateService, useClass: MockContainerTemplateService },
        { provide: PendingChangesService, useClass: MockPendingChangesService },
        { provide: Router, useClass: MockRouter },
        { provide: ActivatedRoute, useValue: { paramMap: paramMap$.asObservable() } }
      ]
    }).compileComponents();

    containerTemplateServiceMock = TestBed.inject(ContainerTemplateService) as unknown as MockContainerTemplateService;
  });

  describe("new template mode (no route param)", () => {
    beforeEach(() => {
      paramMap$.next(convertToParamMap({}));
      createFixture();
    });

    it("should create", () => {
      expect(component).toBeTruthy();
    });

    it("should start as a new (empty) template", () => {
      expect(component.isNewTemplate()).toBeTruthy();
      expect(component.template().name).toBe("");
    });

    it("should show 'New Container Template' as title", () => {
      expect(component.title()).toContain("New");
    });

    it("should correctly compute isDirty when template is modified", () => {
      expect(component.isDirty()).toBeFalsy();
      component.editTemplate({ name: "Changed" });
      expect(component.isDirty()).toBeTruthy();
    });

    it("should detect name conflicts using the service", () => {
      const existing = { name: "Conflict" } as ContainerTemplate;
      containerTemplateServiceMock.templates.set([existing]);

      component.editTemplate({ name: "Conflict" });

      expect(component.nameConflict()).toBeTruthy();
      expect(component.canSaveTemplate()).toBeFalsy();
    });

    it("should add a token to the template", () => {
      const initialCount = component.tokens().length;
      component.onAddToken("totp");
      expect(component.tokens().length).toBe(initialCount + 1);
      expect((component.tokens()[initialCount] as any).type).toBe("totp");
    });

    it("should update a specific token by index", () => {
      component.onAddToken("hotp");
      component.onEditToken({ description: "Updated" } as any, 0);
      expect((component.tokens()[0] as any).description).toBe("Updated");
    });

    it("should remove a token by index", () => {
      component.onAddToken("hotp");
      component.onDeleteToken(0);
      expect(component.tokens().length).toBe(0);
    });

    it("should navigate to templates list and save on successful onSave()", async () => {
      jest.spyOn(containerTemplateServiceMock, "canSaveTemplate").mockReturnValue(true);
      jest.spyOn(containerTemplateServiceMock, "postTemplateEdits").mockResolvedValue(true);

      component.editTemplate({ name: "ValidName" });
      const result = await component.onSave();

      expect(result).toBe(true);
      expect(containerTemplateServiceMock.postTemplateEdits).toHaveBeenCalled();
      expect(mockRouter.navigateByUrl).toHaveBeenCalledWith(ROUTE_PATHS.TOKENS_CONTAINERS_TEMPLATES);
    });

    it("should not navigate if saving fails", async () => {
      jest.spyOn(containerTemplateServiceMock, "canSaveTemplate").mockReturnValue(true);
      jest.spyOn(containerTemplateServiceMock, "postTemplateEdits").mockResolvedValue(false);

      const result = await component.onSave();

      expect(result).toBe(false);
      expect(mockRouter.navigateByUrl).not.toHaveBeenCalled();
    });

    it("should navigate to templates list on cancel", () => {
      component.onCancel();
      expect(mockRouter.navigateByUrl).toHaveBeenCalledWith(ROUTE_PATHS.TOKENS_CONTAINERS_TEMPLATES);
    });
  });

  describe("edit template mode (with route param)", () => {
    beforeEach(() => {
      containerTemplateServiceMock.templates.set([existingTemplate]);
      paramMap$.next(convertToParamMap({ name: existingTemplate.name }));
      createFixture();
    });

    it("should be in edit mode when a name param is provided", () => {
      expect(component.isNewTemplate()).toBeFalsy();
      expect(component.templateName()).toBe(existingTemplate.name);
    });

    it("should show 'Edit Container Template' as title", () => {
      expect(component.title()).toContain("Edit");
    });

    it("should load the existing template from the service", () => {
      expect(component.template().name).toBe(existingTemplate.name);
      expect(component.template().container_type).toBe(existingTemplate.container_type);
    });

    it("should not be dirty initially when loaded from service", () => {
      expect(component.isDirty()).toBeFalsy();
    });

    it("should delete the old template name if renamed during save", async () => {
      jest.spyOn(containerTemplateServiceMock, "canSaveTemplate").mockReturnValue(true);
      jest.spyOn(containerTemplateServiceMock, "postTemplateEdits").mockResolvedValue(true);
      const deleteSpy = jest.spyOn(containerTemplateServiceMock, "deleteTemplate");

      component.editTemplate({ name: "RenamedTemplate" });
      await component.onSave();

      expect(deleteSpy).toHaveBeenCalledWith(existingTemplate.name);
      expect(mockRouter.navigateByUrl).toHaveBeenCalledWith(ROUTE_PATHS.TOKENS_CONTAINERS_TEMPLATES);
    });

    it("should not delete the template when name is unchanged during save", async () => {
      jest.spyOn(containerTemplateServiceMock, "canSaveTemplate").mockReturnValue(true);
      jest.spyOn(containerTemplateServiceMock, "postTemplateEdits").mockResolvedValue(true);
      const deleteSpy = jest.spyOn(containerTemplateServiceMock, "deleteTemplate");

      await component.onSave();

      expect(deleteSpy).not.toHaveBeenCalled();
    });
  });
});
