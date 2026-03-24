---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: prajkarne-bbsi/Claude-skills
# corpus-url: https://github.com/prajkarne-bbsi/Claude-skills/blob/ee5953fb80e7315449e298bc9ffdce5328a6a646/migration_skill.md
# corpus-round: 2026-03-20
# corpus-format: plain_instructions
---
# Performance Management Frontend Migration Skill

## Objective
Migrate and reorganize React + TypeScript code from the `lovable/src` folder to the `frontend/src` folder following a feature-based architecture pattern for multiple features:
- Review Workflows
- Rating Scales
- Evaluation Criteria
- Dashboard

## ⚠️ CURRENT SCOPE LIMITATION
**ONLY work on these THREE features:**
1. **Evaluation Criteria**
2. **Review Workflows**
3. **Rating Scales**

**DO NOT:**
- Create routes for Dashboard or any other features
- Import Dashboard or other feature pages in the main App or routes
- Attempt to migrate or work on any features beyond the three listed above
- Reference or use code from other features (like review forms, sessions, employees, warnings, etc.)

**IGNORE THESE FOLDERS COMPLETELY:**
- `audit-log/` - Do not migrate or use
- `email-notifications/` - Do not migrate or use
- `employee-warnings/` - Do not migrate or use
- `review-forms/` - Do not migrate or use
- `review-sessions/` - Do not migrate or use

**If other feature code exists in the frontend folder, ignore it completely** - do not route to it, import it, or try to make it work.

## Critical Requirements

### ⚠️ IMPORTANT RULES - MUST FOLLOW

1. **PRESERVE THE EXACT UI FROM LOVABLE**: The frontend folder MUST have the EXACT same UI as lovable - same layout, same components, same styling, same behavior. You are ONLY refactoring the code structure and data layer. DO NOT:
   - Change component layouts or structure
   - Modify styling or CSS classes
   - Alter UI behavior or interactions
   - Recreate components from scratch
   - Change the visual appearance in any way
   
   **What you MUST do**: Copy the lovable source code and only make these modifications:
   - Reorganize files into feature-based folder structure
   - Update import paths to match new structure
   - Replace localStorage with backend API calls
   - Remove dummy data and use real API endpoints
   
   **The UI in frontend must be visually identical to lovable** - only the code organization and data source should change.

2. **DO NOT RECREATE THE UI**: Simply copy and reorganize existing code from `lovable/src` to the required `frontend/src` folder structure. DO NOT modify how the UI looks or behaves. Only change import paths and folder locations.

3. **USE EXACT SAME LIBRARIES**: You MUST use the exact same libraries, packages, and dependencies that exist in `lovable/package.json`. DO NOT add your own library choices or substitutes. Copy the exact versions from lovable.

4. **NO DOCUMENTATION FILES**: DO NOT generate any documentation files (README.md, SUMMARY.md, etc.) after completing the migration unless explicitly requested by the user.

5. **REPLACE LOCAL STORAGE WITH BACKEND APIS**: The lovable folder contains prototype code that stores data in local storage (browser storage). In the frontend folder, you MUST rewrite this code to connect to actual backend REST APIs. Replace all localStorage operations with proper HTTP requests (GET, POST, PUT, DELETE) to the backend endpoints defined in `backend/api/v1/`. **Note**: Keep the lovable folder intact - do not delete or modify lovable code.

6. **CLEAN UP AFTER MIGRATION**: Once code is transferred from lovable to frontend:
   - DO NOT use any dummy/mock data in the frontend folder - all data must come from actual backend API endpoints
   - Update ALL import paths to use frontend structure (e.g., `@/components/ui/*` instead of `../lovable/src/components/ui/*`)
   - Replace any hardcoded sample data arrays or mock objects with API calls
   - Ensure all data comes from backend API calls, not from static constants or localStorage
   - **Important**: Keep the lovable folder unchanged - only modify code in the frontend folder

## Source and Target Structure
- **Source**: `lovable/src` - Contains existing React + TypeScript code in a common folder pattern
- **Target**: `frontend/src` - Feature-based architecture with dedicated folders for each feature

## Architecture Guidelines

### Feature-Specific Organization
Place feature-specific code in dedicated feature folders:

#### Review Workflows (`features/review-workflows/`)
- `apis/` - API calls and endpoints specific to review workflows
- `hooks/` - Custom React hooks for review workflows
- `context/` - React context providers for review workflow state
- `components/` - UI components used only in review workflows
- `types/` - TypeScript interfaces/types for review workflows
- `pages/` - Page components for review workflows

#### Rating Scales (`features/rating-scales/`)
- `apis/` - API calls and endpoints specific to rating scales
- `hooks/` - Custom React hooks for rating scales
- `context/` - React context providers for rating scale state
- `components/` - UI components used only in rating scales
- `types/` - TypeScript interfaces/types for rating scales
- `pages/` - Page components for rating scales

#### Evaluation Criteria (`features/evaluation-criteria/`)
- `apis/` - API calls and endpoints specific to evaluation criteria
- `hooks/` - Custom React hooks for evaluation criteria
- `context/` - React context providers for evaluation criteria state
- `components/` - UI components used only in evaluation criteria
- `types/` - TypeScript interfaces/types for evaluation criteria
- `pages/` - Page components for evaluation criteria

#### Dashboard (`features/dashboard/`)
- `apis/` - API calls for dashboard data aggregation
- `hooks/` - Custom React hooks for dashboard
- `components/` - UI components used only in dashboard
- `types/` - TypeScript interfaces/types for dashboard
- `pages/` - Dashboard page component

### Common/Shared Organization
Place reusable, cross-feature code in root-level folders:
- `components/` - Shared UI components used across features
- `pages/` - Common pages used across the application
- `context/` - Global state management contexts
- `hooks/` - Reusable custom hooks
- `types/` - Shared TypeScript types and interfaces
- `styles/` - Global styles and theme definitions
- `utils/` - Utility functions and helpers
- `routes/` - Application routing configuration (import feature pages here)

## Migration Process

### Step 1: Analyze Lovable Source Code
1. Review the `lovable/src` folder structure
2. Identify all feature-related components, hooks, contexts, and utilities for:
   - Review Workflows
   - Rating Scales
   - Evaluation Criteria
   - Dashboard
3. Categorize code as either feature-specific or common/shared

### Step 2: Backend API Analysis

#### For Each Feature, Examine Backend Routes:
- **Review Workflows**: `backend/api/v1/review_workflows/`
- **Rating Scales**: `backend/api/v1/rating_scales/`
- **Evaluation Criteria**: `backend/api/v1/evaluation_criteria/`
- **Dashboard**: Aggregates data from multiple endpoints

#### Document API Endpoints:
   - HTTP methods (GET, POST, PUT, DELETE, PATCH)
   - Path parameters (e.g., `/workflows/:id`, `/scales/:id`, `/criteria/:id`)
   - Query parameters (search, filters, pagination)
   - Request headers (authentication, content-type)
   - Request body schema
   - Response body schema
   - Error responses
   - Validation rules

### Step 3: Frontend Migration

#### A. Review Workflows Migration
1. **Create Feature Structure**:
   ```
   frontend/src/features/review-workflows/
   ├── apis/
   │   └── reviewWorkflowsApi.ts
   ├── hooks/
   │   └── useReviewWorkflows.ts
   ├── context/
   ├── components/
   │   ├── WorkflowList.tsx
   │   ├── WorkflowForm.tsx
   │   └── WorkflowFilters.tsx
   ├── types/
   │   └── index.ts
   └── pages/
       └── ReviewWorkflowsPage.tsx
   ```

2. **Migrate Components**:
   - `WorkflowList` - Display workflows with pagination
   - `WorkflowForm` - Create/edit workflow with validation
   - `WorkflowFilters` - Search and filter controls

3. **Create API Client**:
   - GET /api/v1/workflows - Fetch workflows
   - POST /api/v1/workflows - Create workflow
   - PUT /api/v1/workflows/:id - Update workflow
   - DELETE /api/v1/workflows/:id - Delete workflow

4. **Define Types**:
   - ReviewWorkflowResponse
   - ReviewWorkflowCreateRequest
   - WorkflowStageResponse/Request
   - Query parameters and filters

#### B. Rating Scales Migration
1. **Create Feature Structure**:
   ```
   frontend/src/features/rating-scales/
   ├── apis/
   │   └── ratingScalesApi.ts
   ├── hooks/
   │   └── useRatingScales.ts
   ├── context/
   ├── components/
   │   ├── RatingScaleList.tsx
   │   ├── RatingScaleForm.tsx
   │   ├── RatingScaleFilters.tsx
   │   └── RatingValueManager.tsx
   ├── types/
   │   └── index.ts
   └── pages/
       └── RatingScalesPage.tsx
   ```

2. **Migrate Components**:
   - `RatingScaleList` - Display rating scales with pagination
   - `RatingScaleForm` - Create/edit rating scale with validation
   - `RatingScaleFilters` - Search and filter controls
   - `RatingValueManager` - Manage rating values within a scale

3. **Create API Client**:
   - GET /api/v1/scales - Fetch rating scales
   - POST /api/v1/scales - Create rating scale
   - PUT /api/v1/scales/:id - Update rating scale
   - DELETE /api/v1/scales/:id - Delete rating scale

4. **Define Types**:
   - RatingScaleResponse
   - RatingScaleCreateRequest
   - RatingValueResponse/Request
   - Query parameters and filters

#### C. Evaluation Criteria Migration
1. **Create Feature Structure**:
   ```
   frontend/src/features/evaluation-criteria/
   ├── apis/
   │   └── evaluationCriteriaApi.ts
   ├── hooks/
   │   └── useEvaluationCriteria.ts
   ├── context/
   ├── components/
   │   ├── CriteriaList.tsx
   │   ├── CriteriaForm.tsx
   │   └── CriteriaFilters.tsx
   ├── types/
   │   └── index.ts
   └── pages/
       └── EvaluationCriteriaPage.tsx
   ```

2. **Migrate Components**:
   - `CriteriaList` - Display evaluation criteria with pagination
   - `CriteriaForm` - Create/edit criteria with validation
   - `CriteriaFilters` - Search and filter controls

3. **Create API Client**:
   - GET /api/v1/criteria - Fetch evaluation criteria
   - POST /api/v1/criteria - Create evaluation criteria
   - PUT /api/v1/criteria/:id - Update evaluation criteria
   - DELETE /api/v1/criteria/:id - Delete evaluation criteria

4. **Define Types**:
   - EvaluationCriteriaResponse
   - EvaluationCriteriaCreateRequest
   - Query parameters and filters

#### D. Dashboard Migration
1. **Create Feature Structure**:
   ```
   frontend/src/features/dashboard/
   ├── apis/
   │   └── dashboardApi.ts
   ├── hooks/
   │   └── useDashboardData.ts
   ├── components/
   │   ├── StatisticsCards.tsx
   │   ├── RecentActivity.tsx
   │   ├── QuickActions.tsx
   │   └── SystemHealth.tsx
   ├── types/
   │   └── index.ts
   └── pages/
       └── DashboardPage.tsx
   ```

2. **Migrate Components**:
   - `StatisticsCards` - Display key metrics and counts
   - `RecentActivity` - Show recent system activities
   - `QuickActions` - Quick access to common tasks
   - `SystemHealth` - Display system status indicators

3. **Create API Client**:
   - Aggregate data from multiple endpoints
   - GET /api/v1/workflows?status=A&page=1
   - GET /api/v1/scales?status=A&page=1
   - GET /api/v1/criteria?status=A&page=1
   - Calculate summary statistics

4. **Define Types**:
   - DashboardStatistics
   - ActivityItem
   - QuickAction
   - SystemHealthStatus

#### E. Common Code Migration
1. **Extract shared components to `frontend/src/components/`**:
   - UI component library (buttons, inputs, cards, etc.)
   - StatusBadge
   - EmptyState
   - LoadingSpinner
   - ErrorBoundary

2. **Extract shared hooks to `frontend/src/hooks/`**:
   - useActiveSessionDependencies (if needed cross-feature)
   - useAuth
   - useToast
   - usePagination

3. **Extract shared contexts to `frontend/src/context/`**:
   - AuthContext
   - TenantContext
   - FeatureContext

4. **Extract shared types to `frontend/src/types/`**:
   - Common API types
   - Pagination types
   - Filter types

5. **Extract utilities to `frontend/src/utils/`**:
   - Date formatters
   - Validation helpers
   - API error handlers

#### F. Page Integration
For each feature:
- Create main page that imports all feature components
- Implement state management
- Handle user interactions
- Manage loading and error states
- Export page for routing

#### G. Update Routes
Update `frontend/src/routes/index.tsx`:
```typescript
<Route path="/review-workflows" element={<ReviewWorkflowsPage />} />
<Route path="/rating-scales" element={<RatingScalesPage />} />
<Route path="/evaluation-criteria" element={<EvaluationCriteriaPage />} />
<Route path="/dashboard" element={<DashboardPage />} />
```

### Step 4: API Integration

#### For Each Feature:

1. **Create API Client**:
   - Implement type-safe API calls matching backend endpoints
   - Handle request/response transformations
   - Implement error handling
   - Add authentication headers via axios interceptors
   - Support pagination, filtering, and search

2. **Type Safety**:
   - Define request/response types aligned with backend schemas
   - Create transformation functions (toUI, toRequest)
   - Ensure TypeScript interfaces match backend Pydantic models
   - Include validation rules matching backend

3. **State Management**:
   - Create custom hooks for data fetching and mutations
   - Implement loading, error, and data states
   - Handle pagination state
   - Cache and refresh strategies
   - Optimistic updates where appropriate

#### Specific API Patterns:

**Review Workflows:**
- Workflow CRUD operations
- Workflow stage management
- Status filtering (Active/Inactive)
- Frequency filtering

**Rating Scales:**
- Rating scale CRUD operations
- Rating value management (nested)
- Min/max value validation
- Value ordering

**Evaluation Criteria:**
- Criteria CRUD operations
- Category-based filtering
- Description and guidelines

**Dashboard:**
- Aggregate statistics
- Multi-endpoint data fetching
- Real-time updates (optional)
- Performance metrics

## Validation Checklist

### Review Workflows
- [ ] All review workflow-specific code is in `features/review-workflows/`
- [ ] API calls match backend endpoint definitions
- [ ] Request/response types align with backend schemas
- [ ] Workflow stages validation (exactly 2: employee + supervisor)
- [ ] Frequency options match backend (one-off, monthly, quarterly, semi-annual, annual)
- [ ] Status validation (A for Active, I for Inactive)
- [ ] Feature page imports all necessary components
- [ ] Routes properly configured

### Rating Scales
- [ ] All rating scale-specific code is in `features/rating-scales/`
- [ ] API calls match backend endpoint definitions
- [ ] Request/response types align with backend schemas
- [ ] Rating values validation (min <= max, proper ordering)
- [ ] Nested rating values management working
- [ ] Scale name and description validation
- [ ] Feature page imports all necessary components
- [ ] Routes properly configured

### Evaluation Criteria
- [ ] All evaluation criteria-specific code is in `features/evaluation-criteria/`
- [ ] API calls match backend endpoint definitions
- [ ] Request/response types align with backend schemas
- [ ] Criteria name and description validation
- [ ] Category filtering working correctly
- [ ] Feature page imports all necessary components
- [ ] Routes properly configured

### Dashboard
- [ ] All dashboard-specific code is in `features/dashboard/`
- [ ] Data aggregation from multiple endpoints working
- [ ] Statistics calculations correct
- [ ] Real-time updates (if implemented)
- [ ] Quick actions functional
- [ ] Feature page displays all components
- [ ] Routes properly configured

### Common/Shared
- [ ] Common/shared code is in root-level folders
- [ ] No code duplication between lovable and frontend
- [ ] All imports are correctly updated
- [ ] TypeScript compilation succeeds without errors
- [ ] Shared UI components properly exported
- [ ] Shared hooks accessible to all features
- [ ] Auth and context providers working

## Output
Provide organized, production-ready React + TypeScript code that:
- Follows the feature-based architecture consistently
- Maintains type safety throughout all features
- Matches backend API contracts for all endpoints
- Separates concerns appropriately
- Is maintainable and scalable
- Includes comprehensive documentation for each feature
- Has proper error handling and loading states
- Implements responsive UI design
- Supports pagination, filtering, and search
- Includes data validation matching backend rules

## Feature-Specific Requirements

### Review Workflows
- Support workflow creation with exactly 2 stages
- Validate participant roles (employee and supervisor)
- Support frequency selection (one-off, monthly, quarterly, semi-annual, annual)
- Enable workflow reordering of stages
- Implement status toggling (Active/Inactive)
- Support workflow deletion with confirmation
- Display workflow usage in active sessions (if applicable)

### Rating Scales
- Support dynamic rating value management
- Validate min/max value constraints
- Enable value ordering and reordering
- Support multiple rating scales per system
- Implement rating scale preview
- Handle nested rating values properly
- Display scale usage in review forms (if applicable)

### Evaluation Criteria
- Support criteria creation with name and description
- Enable category-based organization
- Implement search and filtering
- Support criteria editing and deletion
- Display criteria usage in review forms (if applicable)
- Handle long descriptions gracefully

### Dashboard
- Display summary statistics for all features
- Show active vs inactive counts
- Provide quick access to common actions
- Display recent activity/changes
- Show system health indicators
- Implement responsive card layout
- Support data refresh
- Handle empty states gracefully

## Migration Priority

1. **Phase 1**: Review Workflows (Completed)
2. **Phase 2**: Rating Scales
3. **Phase 3**: Evaluation Criteria
4. **Phase 4**: Dashboard
5. **Phase 5**: Shared Components Migration

## Success Criteria

✅ All features migrated and functional
✅ Type-safe API integration for all endpoints
✅ Comprehensive error handling
✅ Proper loading states and UX feedback
✅ Pagination working correctly
✅ Filtering and search operational
✅ Form validation matching backend
✅ Routes properly configured
✅ No TypeScript compilation errors
✅ Code follows consistent patterns
✅ Documentation complete
✅ Ready for production deployment